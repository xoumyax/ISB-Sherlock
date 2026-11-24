"""Parallel, resumable batch extraction over a work list.

Design: workers extract and *return* records; only the parent writes to the
cache. That removes cross-process file-append races entirely, and lets the parent
checkpoint on a fixed cadence so a killed run loses at most one flush.

``maxtasksperchild`` is set because ``pefile`` on hostile input leaks; recycling
workers keeps a 64k-file pass from growing without bound.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from .cache import ExtractionCache
from .extract import ExtractConfig, extract_record

__all__ = ["WorkItem", "BatchConfig", "BatchExtractor"]


@dataclass(frozen=True)
class WorkItem:
    """One sample to extract: expected sha, absolute path, and free-form tags."""

    sha256: str
    path: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BatchConfig:
    workers: int = 32
    #: Records buffered in the parent before a cache flush.
    flush_every: int = 500
    #: Pool chunksize; small because per-file cost varies by orders of magnitude.
    chunksize: int = 4
    #: Recycle workers after N tasks (pefile leaks on malformed input).
    max_tasks_per_child: int = 200
    #: Skip shas already in the cache.
    resume: bool = True
    log_every: int = 2_000


_WORKER_CONFIG: ExtractConfig | None = None


def _worker_init(config: ExtractConfig) -> None:
    global _WORKER_CONFIG
    _WORKER_CONFIG = config


def _worker_extract(item: tuple[str, str, dict]) -> dict[str, Any]:
    sha, path, meta = item
    config = _WORKER_CONFIG or ExtractConfig()
    rec = extract_record(path, config=config, expected_sha256=sha)
    # Carry the manifest identity so a record whose bytes were unreadable is
    # still attributable to the sample that was meant to be there.
    rec["expected_sha256"] = sha
    if rec.get("sha256") is None:
        rec["sha256"] = sha
    if meta:
        rec["meta"] = meta
    return rec


class BatchExtractor:
    """Runs :func:`extract_record` over a work list into an
    :class:`~YaraGen.StaticFeatures.cache.ExtractionCache`."""

    def __init__(
        self,
        cache: ExtractionCache,
        extract_config: ExtractConfig | None = None,
        batch_config: BatchConfig | None = None,
        log: Callable[[str], None] | None = None,
    ):
        self.cache = cache
        self.extract_config = extract_config or ExtractConfig()
        self.batch_config = batch_config or BatchConfig()
        self.log = log or (lambda msg: print(msg, flush=True))

    def pending(self, items: Sequence[WorkItem]) -> list[WorkItem]:
        """Work list minus what the cache already has (the resume filter)."""
        if not self.batch_config.resume:
            return list(items)
        done = self.cache.existing_shas()
        return [it for it in items if it.sha256 not in done]

    def run(self, items: Iterable[WorkItem]) -> dict[str, Any]:
        """Extract everything pending. Returns a summary dict (house style)."""
        items = list(items)
        cfg = self.batch_config
        todo = self.pending(items)
        n_skipped = len(items) - len(todo)
        self.log(
            f"[extract] {len(items)} requested, {n_skipped} cached, {len(todo)} to do"
        )

        summary: dict[str, Any] = {
            "n_requested": len(items),
            "n_skipped_cached": n_skipped,
            "n_extracted": 0,
            "n_written": 0,
            "n_errors": 0,
            "n_pe": 0,
            "errors_by_kind": {},
            "seconds": 0.0,
        }
        if not todo:
            return summary

        payload = [(it.sha256, it.path, it.meta) for it in todo]
        buffer: list[dict[str, Any]] = []
        started = time.time()
        workers = max(1, min(cfg.workers, len(payload)))

        ctx = mp.get_context("fork")
        with ctx.Pool(
            processes=workers,
            initializer=_worker_init,
            initargs=(self.extract_config,),
            maxtasksperchild=cfg.max_tasks_per_child,
        ) as pool:
            for rec in pool.imap_unordered(
                _worker_extract, payload, chunksize=cfg.chunksize
            ):
                buffer.append(rec)
                summary["n_extracted"] += 1
                if rec.get("is_pe"):
                    summary["n_pe"] += 1
                if rec.get("error"):
                    summary["n_errors"] += 1
                    for kind in str(rec["error"]).split(";"):
                        key = kind.split(":")[0]
                        summary["errors_by_kind"][key] = (
                            summary["errors_by_kind"].get(key, 0) + 1)

                if len(buffer) >= cfg.flush_every:
                    summary["n_written"] += self.cache.write_many(buffer)
                    buffer.clear()
                if summary["n_extracted"] % cfg.log_every == 0:
                    rate = summary["n_extracted"] / max(1e-9, time.time() - started)
                    self.log(
                        f"[extract] {summary['n_extracted']}/{len(todo)} "
                        f"({rate:.1f}/s, {summary['n_errors']} errors)"
                    )

        if buffer:
            summary["n_written"] += self.cache.write_many(buffer)
        summary["seconds"] = round(time.time() - started, 2)
        self.log(
            f"[extract] done: {summary['n_written']} written, "
            f"{summary['n_errors']} with errors, {summary['seconds']}s"
        )
        return summary


def cpu_default(reserve: int = 8, cap: int = 64) -> int:
    """Sensible worker count: most cores, leaving headroom for other jobs."""
    return max(1, min(cap, (os.cpu_count() or 8) - reserve))

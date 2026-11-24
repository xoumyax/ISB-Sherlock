"""Sharded, resumable JSONL cache of extraction records.

Layout: ``<root>/<sha256[:2]>.jsonl`` -- 256 shards, so a shard is small enough
to load whole (~90 records for pass 1, ~250 for the vault) and random access
needs no index file to keep in sync with the data.

Writes happen only in the parent process (workers return records; the parent
appends), so there is no cross-process append interleaving to defend against.

Resumability is the point: extraction over 64k vault samples will be interrupted,
and re-reading which shas are already present is far cheaper than redoing the
work. ``existing_shas()`` is the resume primitive.

Known limitation: a sample that could not be read (``missing_file``,
``size_cap_exceeded``) is still cached -- under its manifest sha -- so a visible
failure beats an invisible gap, but **resume will not retry it**. To re-attempt
one after fixing the cause (a mounted path, a raised size cap), delete its record
from its shard, or re-run that scope with ``NO_RESUME=1``.
"""

from __future__ import annotations

import gzip
import json
import os
from collections import OrderedDict
from typing import Any, Iterable, Iterator

__all__ = ["ExtractionCache"]

_SHARD_WIDTH = 2


def _open_maybe_gzip(path: str, mode: str):
    if path.endswith(".gz"):
        return gzip.open(path, mode + "t", encoding="utf-8")
    return open(path, mode, encoding="utf-8")


def _iter_lines(path: str) -> Iterator[str]:
    """Yield lines, tolerating a truncated tail.

    Two truncation modes have to survive, because both occur in practice: a
    half-written JSON line (killed mid-append) and -- for gzip shards -- a
    half-written compressed member, which raises ``EOFError``/``BadGzipFile``
    from the decompressor rather than yielding a short line. A run in progress or
    a killed run must not make the whole shard unreadable, so we keep whatever
    decoded cleanly and stop at the damage.
    """
    try:
        with _open_maybe_gzip(path, "r") as fh:
            while True:
                try:
                    line = fh.readline()
                except (EOFError, OSError, gzip.BadGzipFile, UnicodeDecodeError):
                    return
                if not line:
                    return
                yield line
    except (EOFError, OSError, gzip.BadGzipFile):
        return


def _iter_records_in(path: str) -> Iterator[dict]:
    for line in _iter_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


class ExtractionCache:
    """Reader/writer for the extraction record cache.

    ``compress=True`` writes ``.jsonl.gz`` shards; the reader handles both
    transparently, so a plain pass-1 cache and a compressed vault cache can live
    side by side.
    """

    def __init__(self, root: str, compress: bool = False, max_cached_shards: int = 8):
        self.root = root
        self.compress = compress
        self.max_cached_shards = max_cached_shards
        self._shard_cache: "OrderedDict[str, dict[str, dict]]" = OrderedDict()

    # -- paths ---------------------------------------------------------
    @staticmethod
    def shard_of(sha256: str) -> str:
        return (sha256 or "__")[:_SHARD_WIDTH].lower()

    def shard_path(self, shard: str, for_write: bool = False) -> str:
        plain = os.path.join(self.root, f"{shard}.jsonl")
        return (plain + ".gz") if (for_write and self.compress) else plain

    def shard_read_paths(self, shard: str) -> list[str]:
        """Every existing file for a shard, plain before gz.

        A cache dir can legitimately hold both forms -- e.g. an uncompressed
        pass 1 followed by a compressed vault pass. Reading only one would hide
        the other's records while ``existing_shas()`` still reported them, so
        reads must union both. Plain comes first so gz wins on a duplicate sha,
        matching the last-write-wins rule.
        """
        plain = os.path.join(self.root, f"{shard}.jsonl")
        return [p for p in (plain, plain + ".gz") if os.path.exists(p)]

    def shard_files(self) -> list[str]:
        if not os.path.isdir(self.root):
            return []
        return sorted(
            os.path.join(self.root, f)
            for f in os.listdir(self.root)
            if f.endswith(".jsonl") or f.endswith(".jsonl.gz")
        )

    # -- writing -------------------------------------------------------
    def write_many(self, records: Iterable[dict[str, Any]]) -> int:
        """Append records, grouped by shard. Returns the count written.

        Records lacking a sha256 (unreadable files) are still written, keyed into
        a ``__`` shard, so a failed sample is visible in the cache instead of
        looking like it was never attempted.
        """
        os.makedirs(self.root, exist_ok=True)
        grouped: dict[str, list[dict]] = {}
        for rec in records:
            grouped.setdefault(self.shard_of(rec.get("sha256") or "__"), []).append(rec)

        written = 0
        for shard, recs in grouped.items():
            path = self.shard_path(shard, for_write=True)
            with _open_maybe_gzip(path, "a") as fh:
                for rec in recs:
                    fh.write(json.dumps(rec, ensure_ascii=True) + "\n")
                    written += 1
            self._shard_cache.pop(shard, None)  # invalidate
        return written

    # -- reading -------------------------------------------------------
    def _read_shard(self, shard: str) -> dict[str, dict]:
        """Read a shard from disk, unioning plain + gz, last write wins."""
        out: dict[str, dict] = {}
        for path in self.shard_read_paths(shard):
            for rec in _iter_records_in(path):
                sha = rec.get("sha256")
                if sha:
                    out[sha] = rec           # last write wins (re-extraction)
        return out

    def _load_shard(self, shard: str) -> dict[str, dict]:
        """LRU-cached shard read, for repeated point lookups."""
        if shard in self._shard_cache:
            self._shard_cache.move_to_end(shard)
            return self._shard_cache[shard]
        out = self._read_shard(shard)
        self._shard_cache[shard] = out
        while len(self._shard_cache) > self.max_cached_shards:
            self._shard_cache.popitem(last=False)
        return out

    def get(self, sha256: str) -> dict[str, Any] | None:
        return self._load_shard(self.shard_of(sha256)).get(sha256)

    def has(self, sha256: str) -> bool:
        return self.get(sha256) is not None

    def existing_shas(self) -> set[str]:
        """Every sha present in the cache -- the resume primitive.

        Streams the shard files rather than going through the shard cache, so
        calling this on a 64k-record vault cache does not hold it all in memory.
        """
        out: set[str] = set()
        for path in self.shard_files():
            for rec in _iter_records_in(path):
                sha = rec.get("sha256")
                if sha:
                    out.add(sha)
        return out

    def shard_names(self) -> list[str]:
        """Distinct shard ids present on disk (``aa.jsonl`` and ``aa.jsonl.gz``
        are one shard)."""
        names = {
            os.path.basename(p).split(".", 1)[0] for p in self.shard_files()
        }
        return sorted(names)

    def iter_records(self) -> Iterator[dict[str, Any]]:
        """Stream every record, one shard at a time.

        Resolves duplicate shas with the same last-write-wins rule as
        :meth:`get`, so streaming and point lookups can never disagree about what
        the cache contains. Memory stays bounded to one shard.
        """
        for shard in self.shard_names():
            yield from self._read_shard(shard).values()

    def __len__(self) -> int:
        return len(self.existing_shas())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ExtractionCache({self.root!r}, shards={len(self.shard_files())})"

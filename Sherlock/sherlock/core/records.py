"""Run records: what ran, on which commit, with which config and roots, and when.

Rewritten fresh against V1's ``isb.Selection`` (D11). V1's results carried their
stats and drop reasons but not their provenance: the drivers hard-coded roots, and
nothing recorded which commit produced an output, so after the move no V1 number
could be tied back to its code. Every Sherlock run writes
``ISB_WORK/runs/<experiment>/<arm>/<run_id>/run.json``, one folder per run, holding:

* the git commit of the **git root** (the parent of ``Sherlock/``) and whether the
  work tree was dirty; outside a repository both are ``None`` and ``error`` says
  why, so a run never fails for lack of git;
* the config as plain JSON (dataclasses and paths converted);
* where each root came from (``env:ISB_DATA``, ``yaml:work_root``) and its folder
  name, never its absolute path; an absolute path anywhere in the config is
  refused too (brownie, 23 Nov: no absolute paths in anything shareable);
* start and end times in UTC, ISO 8601 with a ``Z``;
* the status, stats, and drop counts by reason.

A run id is the start time plus a random suffix (``20261123T100000Z-1a2b3c``), so
runs started in the same second never share one. A ``run.json`` is created
exclusively in the run's own folder and never overwritten by another run. Config and
stats are checked as strict JSON when they arrive, not at the end of the run.

Selection and per-stage records join this module when the stages are built (P4).
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any, Protocol

__all__ = [
    "GIT_ROOT",
    "RUN_STATUSES",
    "GitInfo",
    "RunRecord",
    "git_info",
    "read_run_json",
]

#: ``sherlock/core/records.py`` -> ``Sherlock/`` -> the git root. Found from this
#: file, never from the working directory.
GIT_ROOT = Path(__file__).resolve().parents[3]

RUN_STATUSES: tuple[str, ...] = ("running", "ok", "failed")

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class _HasProvenance(Protocol):
    def provenance(self) -> dict[str, Any]: ...


# -- git ----------------------------------------------------------------------


@dataclass(frozen=True)
class GitInfo:
    """The commit a run used; ``error`` is set when it couldn't be read."""

    commit: str | None
    dirty: bool | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"commit": self.commit, "dirty": self.dirty, "error": self.error}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> GitInfo:
        return cls(commit=d.get("commit"), dirty=d.get("dirty"), error=d.get("error"))


def git_info(git_root: Path | None = None) -> GitInfo:
    """HEAD commit and dirty flag of ``git_root`` (default :data:`GIT_ROOT`)."""
    root = GIT_ROOT if git_root is None else git_root
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        return GitInfo(commit=None, dirty=None, error=str(detail).strip()[:500])
    return GitInfo(commit=commit, dirty=bool(status.strip()))


# -- helpers ------------------------------------------------------------------


def _iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        raise ValueError("run times must be timezone-aware (UTC)")
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _jsonable(dataclasses.asdict(obj))
    if isinstance(obj, Mapping):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, PurePath):
        if obj.is_absolute():
            raise ValueError(f"absolute path {str(obj)!r}; give it relative to a root")
        return str(obj)
    if isinstance(obj, str) and obj.startswith("/"):
        raise ValueError(f"absolute path {obj!r}; give it relative to a root")
    if isinstance(obj, list | tuple | set | frozenset):
        items = sorted(obj) if isinstance(obj, set | frozenset) else obj
        return [_jsonable(v) for v in items]
    return obj


def _strict_json(what: str, obj: Any) -> Any:
    """``obj`` as strict JSON (no NaN), or a ValueError naming the problem."""
    try:
        out = _jsonable(obj)
        json.dumps(out, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{what} must be JSON-serialisable (plain values, dataclasses, paths; "
            f"no NaN, no mixed-type sets): {exc}"
        ) from None
    return out


def _new_run_id(started: datetime) -> str:
    """Start time to the second plus a random suffix, so two runs started in
    the same second (a SLURM array, a quick retry) never share an id."""
    stamp = started.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def _check_name(what: str, name: str) -> None:
    if not _NAME.match(name) or ".." in name:
        raise ValueError(
            f"{what} name {name!r} must be one path segment of letters, digits, "
            "'_', '.' or '-'"
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


# -- run record ---------------------------------------------------------------


@dataclass
class RunRecord:
    """One run of one arm of one experiment. Written as ``run.json``."""

    run_id: str
    experiment: str
    arm: str
    git: GitInfo
    config: dict[str, Any]
    roots: dict[str, Any]
    started_at: str
    ended_at: str | None = None
    status: str = "running"
    error: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    #: reason -> number of items dropped for it.
    dropped: dict[str, int] = field(default_factory=dict)
    _clock: Callable[[], datetime] = field(default=_utc_now, repr=False, compare=False)
    #: Set once this record has created its run.json; only then may it rewrite.
    _written: bool = field(default=False, repr=False, compare=False)

    @classmethod
    def start(
        cls,
        experiment: str,
        arm: str,
        config: Any,
        roots: _HasProvenance | Mapping[str, Any],
        *,
        run_id: str | None = None,
        git_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> RunRecord:
        """Open a record: reads git now, stamps the start time."""
        _check_name("experiment", experiment)
        _check_name("arm", arm)
        clock = clock or _utc_now
        started = clock()
        roots_d = roots.provenance() if hasattr(roots, "provenance") else dict(roots)
        config_j = _strict_json("config", config)
        return cls(
            run_id=run_id or _new_run_id(started),
            experiment=experiment,
            arm=arm,
            git=git_info(git_root),
            config=config_j,
            roots=_strict_json("roots", roots_d),
            started_at=_iso(started),
            _clock=clock,
        )

    def finish(
        self,
        status: str = "ok",
        *,
        stats: Mapping[str, Any] | None = None,
        dropped: Mapping[str, Sequence[Any] | int] | None = None,
        error: str | None = None,
    ) -> RunRecord:
        """Close the record: end time, status, stats and drop counts."""
        if status not in RUN_STATUSES or status == "running":
            raise ValueError(f"finish status must be 'ok' or 'failed', got {status!r}")
        if self.status != "running":
            raise ValueError(f"run {self.run_id} already finished ({self.status})")
        stats_j = _strict_json("stats", stats or {})
        self.ended_at = _iso(self._clock())
        self.status = status
        self.error = error
        self.stats.update(stats_j)
        for reason, items in (dropped or {}).items():
            n = items if isinstance(items, int) else len(items)
            self.dropped[reason] = self.dropped.get(reason, 0) + n
        return self

    # -- output --------------------------------------------------------------
    def run_dir(self, work_root: Path) -> Path:
        """``runs/<experiment>/<arm>/<run_id>/``: one folder per run."""
        return work_root / "runs" / self.experiment / self.arm / self.run_id

    def write(self, work_root: Path) -> Path:
        """Write ``run.json`` in this run's own folder; returns its path.

        The record that created the file may rewrite it (start, then finish).
        Any other record finding the file there is refused: that would lose
        another run's commit, config and times.
        """
        out = self.run_dir(work_root)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "run.json"
        if path.exists() and not self._written:
            raise ValueError(
                f"{path} already holds another run's record; start a new run "
                "(a new run id) instead of reusing this one"
            )
        tmp = out / f".run.json.{os.getpid()}.tmp"
        tmp.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True, allow_nan=False)
            + "\n",
            encoding="utf-8",
        )
        if self._written:
            tmp.replace(path)
            return path
        try:
            os.link(tmp, path)  # atomic and exclusive: fails if another run won
        except FileExistsError:
            raise ValueError(
                f"{path} already holds another run's record (created meanwhile)"
            ) from None
        finally:
            tmp.unlink(missing_ok=True)
        self._written = True
        return path

    def summary(self) -> dict[str, Any]:
        duration = None
        if self.ended_at is not None:
            delta = _parse_iso(self.ended_at) - _parse_iso(self.started_at)
            duration = delta.total_seconds()
        return {
            "run_id": self.run_id,
            "experiment": self.experiment,
            "arm": self.arm,
            "status": self.status,
            "commit": self.git.commit,
            "dirty": self.git.dirty,
            "duration_s": duration,
            "dropped": dict(self.dropped),
            **self.stats,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "experiment": self.experiment,
            "arm": self.arm,
            "git": self.git.to_dict(),
            "config": self.config,
            "roots": self.roots,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status,
            "error": self.error,
            "stats": self.stats,
            "dropped": self.dropped,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RunRecord:
        return cls(
            run_id=d["run_id"],
            experiment=d["experiment"],
            arm=d["arm"],
            git=GitInfo.from_dict(d["git"]),
            config=dict(d["config"]),
            roots=dict(d["roots"]),
            started_at=d["started_at"],
            ended_at=d.get("ended_at"),
            status=d["status"],
            error=d.get("error"),
            stats=dict(d.get("stats") or {}),
            dropped=dict(d.get("dropped") or {}),
        )


def read_run_json(path: Path) -> RunRecord:
    return RunRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

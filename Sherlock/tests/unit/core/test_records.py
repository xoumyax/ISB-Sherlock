"""Unit tests for ``sherlock.core.records``: run records and ``run.json``.

The git lookups run against a throwaway repository in ``tmp_path``, so the tests
don't depend on the state of the real checkout.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sherlock.core.records import (
    GIT_ROOT,
    GitInfo,
    RunRecord,
    git_info,
    read_run_json,
)
from sherlock.data.roots import Roots


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "a.txt").write_text("a")
    _git(r, "add", "a.txt")
    _git(r, "commit", "-q", "-m", "init")
    return r


def _clock(*stamps: str) -> Callable[[], datetime]:
    it = iter(datetime.fromisoformat(s) for s in stamps)
    return lambda: next(it)


@dataclass(frozen=True)
class _Cfg:
    k: int = 3
    seed: int = 7


def _roots(tmp_path: Path) -> Roots:
    return Roots(
        dataset=tmp_path / "d",
        work=tmp_path / "w",
        scratch=tmp_path / "s",
        sources={"dataset": "env:ISB_DATA"},
    )


# -- git ----------------------------------------------------------------------


def test_git_root_is_parent_of_sherlock() -> None:
    assert (GIT_ROOT / "Sherlock" / "sherlock" / "core" / "records.py").is_file()
    assert (GIT_ROOT / "README.md").is_file()


def test_git_info_clean_then_dirty(repo: Path) -> None:
    info = git_info(repo)
    assert info.commit == _git(repo, "rev-parse", "HEAD")
    assert info.dirty is False and info.error is None
    (repo / "a.txt").write_text("changed")
    assert git_info(repo).dirty is True


def test_git_info_outside_repo_degrades(tmp_path: Path) -> None:
    info = git_info(tmp_path)
    assert info.commit is None and info.dirty is None
    assert info.error
    assert GitInfo.from_dict(info.to_dict()) == info


# -- run records --------------------------------------------------------------


def test_start_finish_and_round_trip(tmp_path: Path, repo: Path) -> None:
    rec = RunRecord.start(
        experiment="g0_smoke",
        arm="none",
        config=_Cfg(),
        roots=_roots(tmp_path),
        git_root=repo,
        clock=_clock("2026-11-23T10:00:00+00:00", "2026-11-23T10:05:30+00:00"),
    )
    assert rec.status == "running" and rec.ended_at is None
    assert rec.started_at == "2026-11-23T10:00:00Z"
    assert rec.run_id.startswith("20261123T100000Z-")
    assert rec.config == {"k": 3, "seed": 7}
    # Where each root came from and its folder name; never an absolute path.
    assert rec.roots == {
        "dataset": {"source": "env:ISB_DATA", "dir": "d"},
        "work": {"source": None, "dir": "w"},
        "scratch": {"source": None, "dir": "s"},
        "zips": None,
    }
    assert rec.git.commit == _git(repo, "rev-parse", "HEAD")

    rec.finish(stats={"n": 2}, dropped={"no_db_row": ["x", "y"]})
    assert rec.status == "ok"
    assert rec.ended_at == "2026-11-23T10:05:30Z"
    assert rec.dropped == {"no_db_row": 2}
    assert rec.summary()["duration_s"] == 330.0

    path = rec.write(tmp_path / "work")
    run_dir = tmp_path / "work" / "runs" / "g0_smoke" / "none" / rec.run_id
    assert path == run_dir / "run.json"
    d = json.loads(path.read_text())
    assert str(tmp_path) not in path.read_text()  # no absolute path in the record
    assert d["git"]["commit"] == rec.git.commit
    assert read_run_json(path).to_dict() == rec.to_dict()


def test_finish_failed(tmp_path: Path, repo: Path) -> None:
    rec = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo)
    with pytest.raises(ValueError, match="status"):
        rec.finish(status="weird")
    rec.finish(status="failed", error="boom")
    assert rec.status == "failed" and rec.error == "boom"


def test_default_clock_is_utc(tmp_path: Path, repo: Path) -> None:
    rec = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo)
    started = datetime.fromisoformat(rec.started_at.replace("Z", "+00:00"))
    assert started.tzinfo == UTC


@pytest.mark.parametrize("bad", ["../up", "a/b", "", "x y"])
def test_unsafe_names_rejected(tmp_path: Path, repo: Path, bad: str) -> None:
    with pytest.raises(ValueError, match="experiment"):
        RunRecord.start(bad, "a", {}, _roots(tmp_path), git_root=repo)


def test_config_paths_become_strings(tmp_path: Path, repo: Path) -> None:
    rec = RunRecord.start(
        "e", "a", {"p": Path("rel/x"), "n": (1, 2)}, _roots(tmp_path), git_root=repo
    )
    assert rec.config == {"p": "rel/x", "n": [1, 2]}
    json.dumps(rec.to_dict())  # JSON-safe


# -- review fixes (session 2) -------------------------------------------------


def test_each_run_gets_its_own_folder(tmp_path: Path, repo: Path) -> None:
    clock = _clock("2026-11-23T10:00:00+00:00", "2026-11-23T11:00:00+00:00")
    first = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo, clock=clock)
    p1 = first.write(tmp_path / "work")
    first.write(tmp_path / "work")  # a run may rewrite its own record
    second = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo, clock=clock)
    p2 = second.write(tmp_path / "work")
    assert p1.parent != p2.parent
    assert (
        p1.parent.parent == p2.parent.parent == tmp_path / "work" / "runs" / "e" / "a"
    )
    assert read_run_json(p1).run_id == first.run_id
    assert read_run_json(p2).run_id == second.run_id


def test_unserialisable_config_fails_at_start(tmp_path: Path, repo: Path) -> None:
    with pytest.raises(ValueError, match="JSON"):
        RunRecord.start("e", "a", {"x": object()}, _roots(tmp_path), git_root=repo)


def test_finish_twice_raises(tmp_path: Path, repo: Path) -> None:
    rec = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo)
    rec.finish(dropped={"r": [1]})
    with pytest.raises(ValueError, match="already finished"):
        rec.finish(dropped={"r": [1]})
    assert rec.dropped == {"r": 1}


def test_from_dict_requires_status() -> None:
    with pytest.raises(KeyError):
        RunRecord.from_dict(
            {
                "run_id": "r",
                "experiment": "e",
                "arm": "a",
                "git": {"commit": None, "dirty": None},
                "config": {},
                "roots": {},
                "started_at": "2026-11-23T10:00:00Z",
            }
        )


def test_same_second_runs_do_not_collide(tmp_path: Path, repo: Path) -> None:
    clock = _clock("2026-11-23T10:00:00+00:00", "2026-11-23T10:00:00+00:00")
    a = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo, clock=clock)
    b = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo, clock=clock)
    assert a.run_id != b.run_id
    assert a.run_id.startswith("20261123T100000Z-")
    assert a.write(tmp_path / "work") != b.write(tmp_path / "work")


def test_run_folder_taken_by_another_run_is_refused(tmp_path: Path, repo: Path) -> None:
    a = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo, run_id="r1")
    b = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo, run_id="r1")
    b.config["other"] = 1
    a.write(tmp_path / "work")
    with pytest.raises(ValueError, match="already holds"):
        b.write(tmp_path / "work")


@pytest.mark.parametrize(
    "config", [{"p": Path("/abs/x")}, {"p": "/abs/x"}, {"n": {"deep": ["/abs"]}}]
)
def test_absolute_paths_in_config_rejected(
    tmp_path: Path, repo: Path, config: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match="absolute path"):
        RunRecord.start("e", "a", config, _roots(tmp_path), git_root=repo)


@pytest.mark.parametrize("config", [{"s": {1, "a"}}, {"x": float("nan")}])
def test_bad_config_values_fail_at_start(
    tmp_path: Path, repo: Path, config: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match="JSON"):
        RunRecord.start("e", "a", config, _roots(tmp_path), git_root=repo)


def test_bad_stats_fail_at_finish(tmp_path: Path, repo: Path) -> None:
    rec = RunRecord.start("e", "a", {}, _roots(tmp_path), git_root=repo)
    with pytest.raises(ValueError, match="JSON"):
        rec.finish(stats={"x": object()})
    assert rec.status == "running"

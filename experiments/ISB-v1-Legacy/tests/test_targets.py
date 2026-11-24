from __future__ import annotations

import csv
from pathlib import Path

import pytest

from v1repro import targets

FIELDS = ["sha256", "dataset_path", "pool", "kind", "size"]


def sha(c: str) -> str:
    return c * 64


def write_manifest(path: Path, rows: list[dict[str, str]]) -> Path:
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return path


def splits() -> tuple[dict, dict]:
    mal = {
        "samples": {
            sha("a"): {
                "split": "F_dev",
                "side": "held",
                "is_pe": True,
                "family": "fa",
                "path": "old/v1/layout/a.bin",
            },
            sha("b"): {
                "split": "F_dev",
                "side": "gen",
                "is_pe": True,
                "family": "fa",
                "path": "old/b.bin",
            },
            sha("c"): {
                "split": "F_dev",
                "side": "gen",
                "is_pe": False,
                "family": "fa",
                "path": "old/c.bin",
            },
            sha("d"): {
                "split": "F_test",
                "side": "held",
                "is_pe": True,
                "family": "ft",
                "path": "old/d.bin",
            },
        }
    }
    good = {
        "samples": {
            sha("e"): {"side": "G_eval", "source": "Win8", "path": "goodware/x.exe"},
            sha("f"): {"side": "G_stats", "source": "UCSB", "path": "goodware/y.exe"},
            sha("1"): {"side": "G_eval", "source": "UCSB", "path": ""},
        }
    }
    return mal, good


def test_selection_follows_v1_filters() -> None:
    mal, good = splits()
    sel = targets.split_selection(mal, good, "F_dev")
    assert [r["sha256"] for r in sel["held"]] == [sha("a")]
    assert [r["sha256"] for r in sel["gen"]] == [sha("b")]  # non-PE dropped
    assert [r["sha256"] for r in sel["goodware"]] == [sha("e")]  # G_eval with path


def test_resolution_by_sha_uses_manifest_path_and_split_source(
    fake_isb_data: Path,
) -> None:
    # The goodware file sits under a malware pool in the manifest; it still
    # resolves, and its source label comes from the split (Win8), not the pool.
    man = write_manifest(
        fake_isb_data / targets.MANIFEST_REL,
        [
            {
                "sha256": sha("a"),
                "dataset_path": "malware/fa/a.bin",
                "pool": "malware",
                "kind": "pe",
                "size": "3",
            },
            {
                "sha256": sha("b"),
                "dataset_path": "malware/fa/b.bin",
                "pool": "malware",
                "kind": "pe",
                "size": "3",
            },
            {
                "sha256": sha("e"),
                "dataset_path": "malware/_pool_conflicts/e.bin",
                "pool": "malware",
                "kind": "pe",
                "size": "5",
            },
        ],
    )
    manifest = targets.load_manifest(man)
    mal, good = splits()
    sel = targets.split_selection(mal, good)
    root = targets.dataset_root()
    resolved, unresolved = targets.resolve(sel, manifest, root)
    assert unresolved == []
    e = resolved["goodware"][0]
    assert e.path == str(root.resolve() / "malware/_pool_conflicts/e.bin")
    assert e.source == "Win8"
    assert resolved["held"][0].family == "fa"


def test_unresolved_sha_is_reported(fake_isb_data: Path) -> None:
    man = write_manifest(
        fake_isb_data / targets.MANIFEST_REL,
        [
            {
                "sha256": sha("a"),
                "dataset_path": "m/a.bin",
                "pool": "",
                "kind": "",
                "size": "",
            }
        ],
    )
    mal, good = splits()
    _, unresolved = targets.resolve(
        targets.split_selection(mal, good), targets.load_manifest(man), fake_isb_data
    )
    assert sorted(unresolved) == ["gen:0", "goodware:0"]


@pytest.mark.parametrize("bad", ["/abs/x.bin", "../x.bin", "a/../../x.bin", ""])
def test_unsafe_dataset_path_rejected(tmp_path: Path, bad: str) -> None:
    man = write_manifest(
        tmp_path / "m.csv",
        [{"sha256": sha("a"), "dataset_path": bad, "pool": "", "kind": "", "size": ""}],
    )
    with pytest.raises(ValueError):
        targets.load_manifest(man)


def test_conflicting_duplicate_rejected(tmp_path: Path) -> None:
    man = write_manifest(
        tmp_path / "m.csv",
        [
            {
                "sha256": sha("a"),
                "dataset_path": "x/a",
                "pool": "",
                "kind": "",
                "size": "",
            },
            {
                "sha256": sha("a"),
                "dataset_path": "y/a",
                "pool": "",
                "kind": "",
                "size": "",
            },
        ],
    )
    with pytest.raises(ValueError):
        targets.load_manifest(man)


def test_dataset_root_has_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ISB_DATA")
    with pytest.raises(RuntimeError):
        targets.dataset_root()


def test_stat_coverage(fake_isb_data: Path) -> None:
    (fake_isb_data / "m").mkdir()
    (fake_isb_data / "m/a.bin").write_bytes(b"abc")
    (fake_isb_data / "m/b.bin").write_bytes(b"abcdef")
    man = write_manifest(
        fake_isb_data / targets.MANIFEST_REL,
        [
            {
                "sha256": sha("a"),
                "dataset_path": "m/a.bin",
                "pool": "",
                "kind": "",
                "size": "3",
            },
            {
                "sha256": sha("b"),
                "dataset_path": "m/b.bin",
                "pool": "",
                "kind": "",
                "size": "3",
            },
            {
                "sha256": sha("e"),
                "dataset_path": "m/missing.bin",
                "pool": "",
                "kind": "",
                "size": "3",
            },
        ],
    )
    manifest = targets.load_manifest(man)
    mal, good = splits()
    resolved, _ = targets.resolve(
        targets.split_selection(mal, good), manifest, fake_isb_data
    )
    cov = targets.stat_coverage(resolved, manifest)
    assert cov["held"]["ok"] == 1
    assert cov["gen"]["size_mismatch"] == 1
    assert cov["goodware"]["missing"] == 1

from __future__ import annotations

from pathlib import Path

import pytest

from v1repro import common


@pytest.fixture
def protected(tmp_path: Path) -> list[Path]:
    dirs = [tmp_path / "v1_raw", tmp_path / "inputs"]
    for d in dirs:
        d.mkdir()
    return dirs


@pytest.mark.parametrize(
    "rel", ["v1_raw", "inputs", "inputs/run1", "v1_raw/artifacts/x"]
)
def test_refuses_inside_protected(
    tmp_path: Path, protected: list[Path], rel: str
) -> None:
    with pytest.raises(common.OutputDirRefused):
        common.check_output_dir(tmp_path / rel, protected)


def test_refuses_symlink_into_protected(tmp_path: Path, protected: list[Path]) -> None:
    link = tmp_path / "runs_link"
    link.symlink_to(protected[1])
    with pytest.raises(common.OutputDirRefused):
        common.check_output_dir(link / "run1", protected)


def test_refuses_non_empty(tmp_path: Path, protected: list[Path]) -> None:
    out = tmp_path / "runs" / "r1"
    out.mkdir(parents=True)
    (out / "detection.json").write_text("{}")
    with pytest.raises(common.OutputDirRefused):
        common.check_output_dir(out, protected)


def test_accepts_fresh_dir(tmp_path: Path, protected: list[Path]) -> None:
    out = common.check_output_dir(tmp_path / "runs" / "r2", protected)
    assert out.name == "r2"


def test_default_protection_covers_reference_folders(fake_isb_data: Path) -> None:
    names = {p.resolve() for p in common.protected_dirs()}
    assert common.INPUTS_DIR.resolve() in names
    assert common.V1_RAW_DIR.resolve() in names
    assert fake_isb_data.resolve() in names
    with pytest.raises(common.OutputDirRefused):
        common.check_output_dir(common.INPUTS_DIR / "x")
    with pytest.raises(common.OutputDirRefused):
        common.check_output_dir(common.V1_RAW_DIR / "x")
    with pytest.raises(common.OutputDirRefused):
        common.check_output_dir(fake_isb_data / "out")


def test_rel_to_root_never_absolute() -> None:
    rel = common.rel_to_root(common.RUNS_DIR / "stage1" / "x")
    assert rel.startswith("<git root>/experiments/")
    assert not rel.startswith("/")

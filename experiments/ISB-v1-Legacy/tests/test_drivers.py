"""Scan mode and acceptance, end to end, over a fake inputs tree and fake files."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest

from v1repro import acceptance, common
from v1repro.targets import TargetSpec

FAMS = ["amadey", "gcleaner", "guloader", "lummastealer", "njrat", "quasarrat"]
DRIVERS = Path(__file__).resolve().parents[1] / "drivers"


def load_driver(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"drv_{name}", DRIVERS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fake_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    inputs = tmp_path / "inputs"
    for variant in ("gstats", "stock"):
        d = inputs / "artifacts/yargen/rules" / variant
        d.mkdir(parents=True)
        for fam in FAMS:
            name, s = f"{variant}_{fam}", fam.upper()
            text = f'rule {name} {{ strings: $a = "{s}" condition: $a }}'
            (d / f"{fam}.yar").write_bytes(b"/* \x00 */\n" + text.encode())
    monkeypatch.setattr(common, "INPUTS_DIR", inputs)
    return inputs


def fake_targets(tmp: Path) -> dict[str, list[TargetSpec]]:
    files = tmp / "files"
    files.mkdir()

    def make(name: str, data: bytes, kind: str, **kw: str) -> TargetSpec:
        (files / name).write_bytes(data)
        return TargetSpec(
            sha256=name.ljust(64, "0"), path=str(files / name), kind=kind, **kw
        )

    held = [
        make(f"h{i}", f"x{f.upper()}x".encode(), "held", family=f)
        for i, f in enumerate(FAMS)
    ]
    gen = [make("g0", b"AMADEY", "gen", family="amadey")]
    good = [
        make("b0", b"NJRAT", "goodware", source="Win8"),
        make("b1", b"nothing", "goodware", source="UCSB"),
    ]
    return {"held": held, "gen": gen, "goodware": good}


@pytest.fixture
def fake_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        acceptance, "EXPECTED_TARGETS", {"held": 6, "gen": 1, "goodware": 2}
    )


def test_full_run_then_acceptance(
    tmp_path: Path, fake_inputs: Path, fake_counts: None
) -> None:
    stage1 = load_driver("stage1_rescore")
    out = tmp_path / "run"
    done = stage1.full_run(["yargen"], fake_targets(tmp_path), out)
    assert done["yargen"]["n_compiled"] == 12
    det = json.loads((out / "yargen/detection.json").read_text())
    assert {"per_unit", "compile", "warnings", "failures"} <= det.keys()
    assert det["per_unit"]["yargen_stock__njrat"]["benign_by_source"] == {"Win8": 1}
    assert det["per_unit"]["yargen_gstats__amadey"]["gen_match"] == 1

    # V1's reference = this run's own result, so acceptance must pass.
    ref = fake_inputs / acceptance.SCANS["yargen"]["ref"]
    shutil.copy(out / "yargen/detection.json", ref)
    (fake_inputs / "INPUTS.sha256").write_text(
        f"{common.sha256_file(ref)}  {acceptance.SCANS['yargen']['ref']}\n"
    )
    (out / "run.json").write_text(
        json.dumps({"mode": "scan", "scans_done": ["yargen"], "limit": None})
    )
    accept = load_driver("acceptance")
    # yarGen alone passes, but one scan of three is PARTIAL, never PASS.
    assert accept.main(["--run-dir", str(out)]) == 1
    verdict = json.loads((out / "acceptance.json").read_text())
    assert verdict["status"] == "PARTIAL" and verdict["scans"]["yargen"]["pass"]
    assert verdict["scans_missing"] == ["template", "generators"]


def test_acceptance_rejects_tampered_reference(
    tmp_path: Path, fake_inputs: Path
) -> None:
    stage1 = load_driver("stage1_rescore")
    out = tmp_path / "run"
    stage1.full_run(["yargen"], fake_targets(tmp_path), out)
    ref = fake_inputs / acceptance.SCANS["yargen"]["ref"]
    shutil.copy(out / "yargen/detection.json", ref)
    (fake_inputs / "INPUTS.sha256").write_text(
        f"{'0' * 64}  {acceptance.SCANS['yargen']['ref']}\n"
    )
    (out / "run.json").write_text(
        json.dumps({"mode": "scan", "scans_done": ["yargen"], "limit": None})
    )
    with pytest.raises(RuntimeError):
        load_driver("acceptance").main(["--run-dir", str(out)])

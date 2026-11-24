"""Review fixes: provenance, run.json lifecycle, main() guards, acceptance, extract."""

from __future__ import annotations

import importlib.util
import json
import stat
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import fakes
import pytest
import yara

from v1repro import acceptance, common, scan, stage0, targets

EXP = Path(__file__).resolve().parents[1]


def load(rel: str) -> ModuleType:
    path = EXP / rel
    spec = importlib.util.spec_from_file_location(f"m_{path.stem}", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def world(tmp_path: Path, fake_isb_data: Path, monkeypatch: pytest.MonkeyPatch):
    inputs = tmp_path / "exp" / "inputs"
    fakes.build_inputs(inputs)
    fakes.build_dataset(fake_isb_data)
    monkeypatch.setattr(common, "INPUTS_DIR", inputs)
    monkeypatch.setattr(common, "RUNS_DIR", tmp_path / "exp" / "runs")
    monkeypatch.setattr(common, "V1_RAW_DIR", tmp_path / "exp" / "v1_raw")
    drv = load("drivers/stage1_rescore.py")
    monkeypatch.setattr(drv, "hash_seed_ok", lambda: True)
    return {"inputs": inputs, "data": fake_isb_data, "drv": drv, "tmp": tmp_path}


def run_json(out: Path) -> dict[str, Any]:
    return json.loads((out / "run.json").read_text())


# ---------------------------------------------------------------- provenance
def test_code_hashes_cover_code_and_harness() -> None:
    hashes = common.code_hashes()
    keys = set(hashes)
    for rel in (
        "v1repro/common.py",
        "drivers/stage1_rescore.py",
        "slurm/stage1.sbatch",
        "tools/extract_inputs.py",
    ):
        assert f"<git root>/experiments/ISB-v1-Legacy/{rel}" in keys
    assert "<git root>/Sherlock/legacy/V1/YaraGen/Detection/harness.py" in keys
    assert not any("__pycache__" in k or k.startswith("/") for k in keys)
    assert all(len(v) == 64 for v in hashes.values())


def test_run_record_has_versions_job_id_and_experiment_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SLURM_JOB_ID", "12345")
    rec = common.run_record("stage1", "r", "t0", {})
    assert rec["yara_version"] == yara.__version__
    assert rec["python"].count(".") == 2
    assert rec["slurm_job_id"] == "12345"
    assert "code_sha256" in rec
    assert "experiment_status" in rec["git"]
    assert isinstance(rec["git"]["experiment_dirty"], bool)


def test_atomic_replace(tmp_path: Path) -> None:
    p = tmp_path / "run" / "run.json"
    common.write_json_atomic(p, {"status": "running"})
    common.write_json_atomic(p, {"status": "complete"})
    assert json.loads(p.read_text()) == {"status": "complete"}
    assert [x.name for x in p.parent.iterdir()] == ["run.json"]


# ---------------------------------------------------------------- targets
def test_load_targets_on_fake_split_and_manifest(world: dict) -> None:
    tgts, cov = world["drv"].load_targets(None)
    assert cov["selected"] == {"held": 2, "gen": 1, "goodware": 2}
    assert cov["unresolved"] == 0
    assert all(c["ok"] == c["n"] for c in cov["stat"].values())
    assert {t.source for t in tgts["goodware"]} == {"Win8", "UCSB"}
    assert all(t.path.startswith(str(world["data"].resolve())) for t in tgts["held"])


def test_load_targets_limit(world: dict) -> None:
    tgts, _ = world["drv"].load_targets(1)
    assert {k: len(v) for k, v in tgts.items()} == {"held": 1, "gen": 1, "goodware": 1}


def test_load_targets_refuses_unresolved(world: dict) -> None:
    man = world["data"] / targets.MANIFEST_REL
    lines = man.read_text().splitlines()
    man.write_text("\n".join(lines[:-3]) + "\n")  # drop e, f, 1
    with pytest.raises(SystemExit):
        world["drv"].load_targets(None)


# ---------------------------------------------------------------- main()
def test_main_refuses_without_hash_seed(
    world: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(world["drv"], "hash_seed_ok", lambda: False)
    with pytest.raises(SystemExit, match="PYTHONHASHSEED"):
        world["drv"].main(["--dry-run"])


def test_main_refuses_out_dir_in_inputs(world: dict) -> None:
    with pytest.raises(common.OutputDirRefused):
        world["drv"].main(["--dry-run", "--out-dir", str(world["inputs"] / "x")])


def test_main_default_out_dir_is_runs_stage1(world: dict) -> None:
    assert world["drv"].main(["--dry-run", "--run-id", "dry1"]) == 0
    out = common.RUNS_DIR / "stage1" / "dry1"
    rec = run_json(out)
    assert rec["status"] == "complete" and rec["mode"] == "dry-run"
    assert rec["dry_run"]["template"]["n_compiled"] == 2
    assert not (out / "template").exists()  # nothing scanned


def test_main_refuses_scan_when_stat_fails(world: dict) -> None:
    fakes.build_dataset(world["data"], missing=(fakes.sha("e"),))
    (world["data"] / f"pool/ee/{fakes.sha('e')}.bin").unlink()
    with pytest.raises(SystemExit, match="stat check"):
        world["drv"].main(["--scan", "yargen", "--run-id", "s1"])
    assert run_json(common.RUNS_DIR / "stage1" / "s1")["status"] == "failed"


def test_end_to_end_template_and_generators(world: dict) -> None:
    for name in ("template", "generators"):
        assert world["drv"].main(["--scan", name, "--run-id", f"e2e-{name}"]) == 0
    out_t = common.RUNS_DIR / "stage1" / "e2e-template"
    det = json.loads((out_t / "template/detection.json").read_text())
    u = det["per_unit"]["static__prevalence_k__fa"]
    assert (u["tp"], u["gen_match"], u["benign_match"]) == (1, 1, 1)
    assert u["benign_by_source"] == {"Win8": 1}
    assert det["compile"]["n_over_string_limit"] == 1
    assert "static__all__fa" in det["unrenderable"]
    assert det["n_targets"] == {"held": 2, "gen": 1, "goodware": 2}

    out_g = common.RUNS_DIR / "stage1" / "e2e-generators"
    det = json.loads((out_g / "generators/detection.json").read_text())
    # 22 tags x 2 non-empty units + 3 template units
    assert det["compile"]["n_units"] == 22 * 2 + 3
    assert len(det["compile_errors"]) == 22 + 1
    assert det["per_unit"]["bart_planformat::static__prevalence_k__fa__bart"]["tp"] == 1
    assert det["unit_meta"]["m4::static__all__fa"]["prompt_style"] == "describer"
    rec = run_json(out_g)
    assert rec["status"] == "complete" and rec["scans_done"] == ["generators"]


def test_failed_scan_leaves_partial_record(
    world: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = scan.run_scan
    calls: list[int] = []

    def flaky(*a: Any, **k: Any) -> dict:
        calls.append(1)
        if len(calls) == 2:
            raise MemoryError("boom")
        return real(*a, **k)

    monkeypatch.setattr(scan, "run_scan", flaky)
    with pytest.raises(MemoryError):
        world["drv"].main(["--run-id", "crash"])
    out = common.RUNS_DIR / "stage1" / "crash"
    rec = run_json(out)
    assert rec["status"] == "failed" and rec["error"] == "MemoryError"
    assert rec["scans_done"] == ["template"]
    assert (out / "template/detection.json").exists()


def test_timeout_is_counted_as_failure(
    world: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SlowRules:
        def match(self, **_kw: Any) -> list:
            raise yara.TimeoutError("timed out")

    real = scan.compile_units

    def patched(us: Any, progress: Any = None) -> tuple:
        h, summary = real(us, progress)
        h.rules = SlowRules()
        return h, summary

    monkeypatch.setattr(scan, "compile_units", patched)
    tgts, _ = world["drv"].load_targets(None)
    res = scan.run_scan([u for u in fakes_units()], tgts)
    assert res["failures"]["held"] == {"timeout": 2}
    assert res["failures"]["goodware"] == {"timeout": 2}
    assert acceptance.compare_failures(res)


def fakes_units() -> list[dict]:
    from v1repro import units

    return units.template_units(fakes.template_rules())


# ---------------------------------------------------------------- acceptance
def accept_world(world: dict, scans: list[str]) -> Path:
    out = common.RUNS_DIR / "stage1" / "acc"
    assert world["drv"].main(["--run-id", "acc", "--scan", "yargen"]) == 0
    det_path = out / "yargen/detection.json"
    ref = world["inputs"] / acceptance.SCANS["yargen"]["ref"]
    ref.chmod(0o644)
    ref.write_text(det_path.read_text())
    fakes.write_index(world["inputs"])
    rec = run_json(out)
    rec["scans_done"] = scans
    (out / "run.json").write_text(json.dumps(rec))
    return out


@pytest.fixture
def lenient(monkeypatch: pytest.MonkeyPatch) -> None:
    """Expected counts matching the fake world instead of V1's."""
    monkeypatch.setitem(
        acceptance.SCANS,
        "yargen",
        {**acceptance.SCANS["yargen"], "n_units": 4, "n_compiled": 4},
    )
    monkeypatch.setattr(
        acceptance, "EXPECTED_TARGETS", {"held": 2, "gen": 1, "goodware": 2}
    )


def test_acceptance_partial_never_passes(
    world: dict, lenient: None, capsys: pytest.CaptureFixture
) -> None:
    out = accept_world(world, ["yargen"])
    rc = load("drivers/acceptance.py").main(["--run-dir", str(out)])
    assert rc != 0
    printed = capsys.readouterr().out
    assert "PARTIAL" in printed and "acceptance: PASS" not in printed
    assert json.loads((out / "acceptance.json").read_text())["status"] == "PARTIAL"


def test_acceptance_does_not_overwrite(world: dict, lenient: None) -> None:
    out = accept_world(world, ["yargen"])
    mod = load("drivers/acceptance.py")
    mod.main(["--run-dir", str(out)])
    first = (out / "acceptance.json").read_text()
    mod.main(["--run-dir", str(out)])
    assert (out / "acceptance.json").read_text() == first
    assert len(list(out.glob("acceptance*.json"))) == 2


def test_acceptance_refuses_protected_run_dir(world: dict) -> None:
    with pytest.raises(common.OutputDirRefused):
        load("drivers/acceptance.py").main(["--run-dir", str(world["inputs"])])


def test_target_counts_are_checked() -> None:
    got = {"n_targets": {"held": 521, "gen": 527, "goodware": 9947}}
    bad = acceptance.compare_targets(got)
    assert bad and "held" in bad[0]
    ok = {"n_targets": {"held": 522, "gen": 527, "goodware": 9947}}
    assert acceptance.compare_targets(ok) == []


def test_overall_status() -> None:
    passing = {"pass": True}
    assert acceptance.overall({s: passing for s in acceptance.SCANS}) == "PASS"
    assert acceptance.overall({"yargen": passing}) == "PARTIAL"
    assert acceptance.overall({"yargen": {"pass": False}}) == "FAIL"


# ---------------------------------------------------------------- stage 0
def test_stage0_kinds_keep_internal_checks_out_of_the_count() -> None:
    results = {
        "R": {
            "a": stage0.check("1", 1, None),
            "b": stage0.check("2", 2, None, kind="derived"),
            "c": stage0.check("3", 3, None, kind="internal"),
        }
    }
    s = stage0.summarize(results)
    assert s["report"] == {"n_checks": 1, "n_pass": 1}
    assert s["derived"] == {"n_checks": 1, "n_pass": 1}
    assert s["internal"] == {"n_checks": 1, "n_pass": 1}
    assert results["R"]["c"]["kind"] == "internal (not from the report)"


# ---------------------------------------------------------------- extract
ZIP_PREFIX = "some/old/home/finalexperimets/e2e-experiment/"


def test_extract_finds_prefix(tmp_path: Path) -> None:
    ex = load("tools/extract_inputs.py")
    with zipfile.ZipFile(_zip_with(tmp_path, [])) as zf:
        assert ex.find_prefix(zf) == ZIP_PREFIX


def _zip_with(tmp: Path, extra: list[tuple[zipfile.ZipInfo, bytes]]) -> Path:
    ex = load("tools/extract_inputs.py")
    zpath = tmp / "fake.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for rel in ex.allow_list():
            data = b"x"
            if rel.endswith(".sha256"):
                import hashlib

                data = hashlib.sha256(b"x").hexdigest().encode()
            zf.writestr(ZIP_PREFIX + rel, data)
        for info, data in extra:
            zf.writestr(info, data)
    return zpath


def test_extract_refuses_traversal_member(tmp_path: Path) -> None:
    ex = load("tools/extract_inputs.py")
    zpath = _zip_with(tmp_path, [(zipfile.ZipInfo(ZIP_PREFIX + "../../evil"), b"e")])
    dest = tmp_path / "dest"
    with pytest.raises(RuntimeError, match="unsafe"):
        ex.main(["--zip", str(zpath), "--dest", str(dest)])
    assert not any(p.is_file() for p in dest.rglob("*"))
    assert not (tmp_path / "evil").exists()


def test_extract_refuses_symlink_member(tmp_path: Path) -> None:
    ex = load("tools/extract_inputs.py")
    link = zipfile.ZipInfo(ZIP_PREFIX + "artifacts/link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    zpath = _zip_with(tmp_path, [(link, b"/etc/passwd")])
    with pytest.raises(RuntimeError, match="unsafe"):
        ex.main(["--zip", str(zpath), "--dest", str(tmp_path / "dest")])


def test_extract_clean_zip(tmp_path: Path) -> None:
    ex = load("tools/extract_inputs.py")
    zpath = _zip_with(tmp_path, [])
    dest = tmp_path / "dest"
    assert ex.main(["--zip", str(zpath), "--dest", str(dest)]) == 0
    lines = (dest / "INPUTS.sha256").read_text().splitlines()
    assert len(lines) == len(ex.allow_list())


def test_acceptance_reads_records_without_scans_done(tmp_path: Path) -> None:
    mod = load("drivers/acceptance.py")
    (tmp_path / "yargen").mkdir()
    (tmp_path / "yargen/detection.json").write_text("{}")
    old = {"mode": "scan", "scans": ["template", "yargen", "generators"]}
    assert mod.scans_completed(old, tmp_path) == ["yargen"]
    assert mod.scans_completed({**old, "scans_done": []}, tmp_path) == []

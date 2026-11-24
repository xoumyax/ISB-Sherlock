"""Stage 1 acceptance: compare a run's per-scan detection.json with V1's, exactly.

Usage, from the git root:
    python -I experiments/ISB-v1-Legacy/drivers/acceptance.py \\
        --run-dir experiments/ISB-v1-Legacy/runs/stage1/<run_id>

Writes ``acceptance.json`` into the run folder (or a new timestamped file if one
exists). Overall PASS needs all three scans to pass; fewer is PARTIAL. Exit 0
only on PASS.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v1repro import acceptance, common  # noqa: E402


def output_path(run_dir: Path) -> Path:
    """``acceptance.json``, or a new timestamped name: never overwrite a verdict."""
    path = run_dir / "acceptance.json"
    stamp = common.new_run_id()
    n = 0
    while path.exists():
        n += 1
        path = run_dir / f"acceptance-{stamp}{'' if n == 1 else f'-{n}'}.json"
    return path


def scans_completed(record: dict, run_dir: Path) -> list[str]:
    """``scans_done`` from run.json; records written before it existed fall back
    to the planned scans whose detection.json is present."""
    if "scans_done" in record:
        return list(record["scans_done"])
    return [
        s for s in record.get("scans", []) if (run_dir / s / "detection.json").exists()
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage 1 acceptance")
    ap.add_argument("--run-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    run_dir = common.check_output_dir(args.run_dir, require_empty=False)
    record = common.load_json(run_dir / "run.json")
    if record.get("mode") != "scan":
        raise SystemExit("not a scan run (dry-run records have nothing to compare)")
    done = scans_completed(record, run_dir)
    common.verified_inputs([acceptance.SCANS[s]["ref"] for s in done])
    results = {}
    for name in done:
        got = common.load_json(run_dir / name / "detection.json")
        ref = common.load_json(common.INPUTS_DIR / acceptance.SCANS[name]["ref"])
        results[name] = acceptance.compare_scan(name, got, ref, record.get("limit"))
    status = acceptance.overall(results)
    missing = [s for s in acceptance.SCANS if s not in results]
    out = output_path(run_dir)
    common.write_json(
        out,
        {
            "status": status,
            "pass": status == "PASS",
            "run_status": record.get("status"),
            "scans_missing": missing,
            "scans": results,
        },
    )
    for name, r in results.items():
        flag = "PASS" if r["pass"] else "FAIL"
        print(
            f"{flag}  {name:<11} units={r['n_units_compared']}"
            f" mismatches={r['n_mismatches']} warnings={r['warnings']}"
        )
        for m in r["mismatches"][:10]:
            print(f"      {m}")
    if missing:
        print(f"missing scans: {missing}")
    print(f"Stage 1 acceptance: {status} ({out.name})")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

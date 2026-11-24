"""Stage 1 acceptance: compare a run's per-scan detection.json with V1's, exactly.

Usage, from the git root:
    python -I experiments/ISB-v1-Legacy/drivers/acceptance.py \\
        --run-dir experiments/ISB-v1-Legacy/runs/stage1/<run_id>

Writes ``acceptance.json`` into the run folder; exit 0 only if every scan passes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v1repro import acceptance, common  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage 1 acceptance")
    ap.add_argument("--run-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    run_dir = args.run_dir.resolve()
    record = common.load_json(run_dir / "run.json")
    if record.get("mode") != "scan":
        raise SystemExit("not a scan run (dry-run records have nothing to compare)")
    common.verified_inputs([acceptance.SCANS[s]["ref"] for s in record["scans"]])
    results = {}
    for name in record["scans"]:
        got = common.load_json(run_dir / name / "detection.json")
        ref = common.load_json(common.INPUTS_DIR / acceptance.SCANS[name]["ref"])
        results[name] = acceptance.compare_scan(name, got, ref, record.get("limit"))
    ok = all(r["pass"] for r in results.values())
    common.write_json(
        run_dir / "acceptance.json", {"pass": ok, "scans": results}, overwrite=True
    )
    for name, r in results.items():
        flag = "PASS" if r["pass"] else "FAIL"
        print(
            f"{flag}  {name:<11} units={r['n_units_compared']}"
            f" mismatches={r['n_mismatches']} warnings={r['warnings']}"
        )
        for m in r["mismatches"][:10]:
            print(f"      {m}")
    print("Stage 1 acceptance:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

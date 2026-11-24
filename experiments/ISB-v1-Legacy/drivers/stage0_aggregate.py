"""Stage 0 (login node): re-aggregate V1's stored detection.json into R1, R2, R4, R7.

Reads only ``inputs/`` (each file checked against ``inputs/INPUTS.sha256``) and
writes ``runs/stage0/<run_id>/{stage0.json,run.json}``. Arithmetic only.

Run from the git root:
    python -I experiments/ISB-v1-Legacy/drivers/stage0_aggregate.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v1repro import common, stage0  # noqa: E402

DETECTIONS = {
    "m4": "artifacts/exp2__m4/detection.json",
    "yargen": "artifacts/yargen/detection.json",
    "all": "artifacts/exp2_all/detection.json",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage 0 re-aggregation")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args(argv)
    run_id = args.run_id or common.new_run_id()
    out = common.check_output_dir(common.RUNS_DIR / "stage0" / run_id)
    started = common.utc_now()

    yar_dir = common.INPUTS_DIR / "artifacts/yargen/rules"
    yar_rels = sorted(
        p.relative_to(common.INPUTS_DIR).as_posix() for p in yar_dir.glob("*/*.yar")
    )
    hashes = common.verified_inputs([*DETECTIONS.values(), *yar_rels])
    dets = {
        k: common.load_json(common.INPUTS_DIR / rel) for k, rel in DETECTIONS.items()
    }
    results = stage0.aggregate(
        dets["m4"], dets["yargen"], dets["all"], stage0.count_yargen_rules(yar_dir)
    )

    common.write_json(out / "stage0.json", results)
    common.write_json(
        out / "run.json",
        common.run_record(
            "stage0",
            run_id,
            started,
            hashes,
            {"outputs": ["stage0.json"], "out_dir": common.rel_to_root(out)},
        ),
    )

    summ = results["summary"]
    for path, c in stage0.iter_checks(results):
        flag = "PASS" if c["pass"] else "FAIL"
        tag = "" if c["kind"] == "report" else f"  [{c['kind']}]"
        print(f"{flag}  {path:<62} expected {c['expected']:>9}  got {c['got']:>9}{tag}")
    for kind in stage0.KINDS:
        k = summ[kind]
        print(f"{kind:>9}: {k['n_pass']}/{k['n_checks']} pass")
    print(f"run {run_id} -> {common.rel_to_root(out)}")
    return 0 if not summ["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())

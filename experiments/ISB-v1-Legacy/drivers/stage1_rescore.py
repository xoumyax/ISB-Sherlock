"""Stage 1: re-score V1's stored rules with V1's harness, three scans as V1 ran them.

Scans (REPRO_PLAN §e, Stage 1): ``template`` (108 units, job 95876), ``yargen``
(12 units, job 95891) and ``generators`` (23 pinned tags, 1,956 units, job
95929), each against F_dev held (522) + gen (527) + G_eval (9,947). Targets come
from V1's split files and are resolved by sha256 through the Sherlock manifest
under ``ISB_DATA``.

``--dry-run`` stat()s every target (no sample bytes are read) and compiles every
rule, but scans nothing. ``--limit N`` keeps the first N targets of each corpus
(a smoke run; never an acceptance run).

Needs ``PYTHONHASHSEED=0``. ``python -I`` ignores that variable, so run with
``-P -s`` instead (no script dir or cwd on sys.path, no user site), from the
git root:
    PYTHONHASHSEED=0 ISB_DATA=... python -P -s \\
        experiments/ISB-v1-Legacy/drivers/stage1_rescore.py [--dry-run]
"""

from __future__ import annotations

import argparse
import gc
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v1repro import acceptance, common, scan, targets, units  # noqa: E402

SPLIT_RELS = [
    "artifacts/splits/malware_split.json",
    "artifacts/splits/goodware_split.json",
]
SCAN_ORDER = ("template", "yargen", "generators")


def log(msg: str) -> None:
    print(f"[stage1] {msg}", flush=True)


def input_rels(scans: list[str]) -> list[str]:
    rels = list(SPLIT_RELS)
    if "template" in scans or "generators" in scans:
        rels.append(units.rules_rel(units.TEMPLATE_TAG))
    if "generators" in scans:
        rels += [
            units.rules_rel(t) for t in units.GENERATOR_TAGS if t != units.TEMPLATE_TAG
        ]
    if "yargen" in scans:
        rels += sorted(
            p.relative_to(common.INPUTS_DIR).as_posix()
            for p in (common.INPUTS_DIR / "artifacts/yargen/rules").glob("*/*.yar")
        )
    return [*rels, *(acceptance.SCANS[s]["ref"] for s in scans)]


def build_units(scan_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(units, extra fields for the output) for one scan."""
    if scan_name == "template":
        rules = common.load_json(
            common.INPUTS_DIR / units.rules_rel(units.TEMPLATE_TAG)
        )
        return units.template_units(rules), {"unrenderable": units.unrenderable(rules)}
    if scan_name == "yargen":
        return units.yargen_units(common.INPUTS_DIR / "artifacts/yargen/rules"), {}
    out: list[dict[str, Any]] = []
    for tag in units.GENERATOR_TAGS:
        rules = common.load_json(common.INPUTS_DIR / units.rules_rel(tag))
        out += units.generator_units(tag, rules)
    meta = {
        u["unit_id"]: {k: u["meta"][k] for k in ("generator", "prompt_style", "tag")}
        for u in out
    }
    return out, {"unit_meta": meta}


def load_targets(limit: int | None) -> tuple[dict[str, list], dict[str, Any]]:
    mal = common.load_json(common.INPUTS_DIR / SPLIT_RELS[0])
    good = common.load_json(common.INPUTS_DIR / SPLIT_RELS[1])
    root = targets.dataset_root()
    manifest = targets.load_manifest(root / targets.MANIFEST_REL)
    selection = targets.split_selection(mal, good, "F_dev")
    resolved, unresolved = targets.resolve(selection, manifest, root)
    if unresolved:
        raise SystemExit(
            f"{len(unresolved)} split entries do not resolve "
            f"through the manifest; refusing"
        )
    if limit:
        resolved = {k: v[:limit] for k, v in resolved.items()}
    coverage = targets.stat_coverage(resolved, manifest)
    return resolved, {
        "selected": {k: len(v) for k, v in selection.items()},
        "unresolved": len(unresolved),
        "stat": coverage,
    }


def coverage_ok(cov: dict[str, Any]) -> bool:
    return all(c["ok"] == c["n"] for c in cov["stat"].values())


def dry_run(scans: list[str], out: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in scans:
        us, _extra = build_units(name)
        _h, summary = scan.compile_units(us, progress=log)
        ref = common.load_json(common.INPUTS_DIR / acceptance.SCANS[name]["ref"])
        bad = acceptance.compare_compile(name, summary, ref)
        result[name] = {
            k: summary[k]
            for k in ("n_units", "n_compiled", "n_over_string_limit", "compile_seconds")
        }
        result[name]["n_compile_errors"] = len(summary["compile_errors"])
        result[name]["compile_matches_v1"] = not bad
        result[name]["compile_mismatches"] = bad
        del _h, us
        gc.collect()
    common.write_json(out / "dryrun.json", result)
    return result


def full_run(scans: list[str], tgts: dict[str, list], out: Path) -> dict[str, Any]:
    done: dict[str, Any] = {}
    for name in scans:
        log(f"--- scan {name}")
        t0 = time.time()
        us, extra = build_units(name)
        res = scan.run_scan(us, tgts, progress=log)
        res.update(extra)
        common.write_json(out / name / "detection.json", res)
        done[name] = {
            "n_compiled": res["compile"]["n_compiled"],
            "failures": res["failures"],
            "warnings": res["warnings"],
            "seconds": round(time.time() - t0, 1),
        }
        log(f"{name}: {done[name]}")
        del us, res
        gc.collect()
    return done


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Stage 1 re-score (V1 harness)")
    ap.add_argument("--scan", choices=[*SCAN_ORDER, "all"], default="all")
    ap.add_argument("--run-id", default=None)
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="default runs/stage1/<run_id>; never inside v1_raw/ or inputs/",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if sys.flags.hash_randomization:
        raise SystemExit(
            "PYTHONHASHSEED=0 is required (and python -I ignores it; use -P -s)"
        )
    run_id = args.run_id or common.new_run_id()
    out = common.check_output_dir(args.out_dir or common.RUNS_DIR / "stage1" / run_id)
    started = common.utc_now()
    scans = list(SCAN_ORDER) if args.scan == "all" else [args.scan]

    hashes = common.verified_inputs(input_rels(scans))
    tgts, cov = load_targets(args.limit)
    log(f"targets {cov['selected']}; stat {cov['stat']}")
    out.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        body = {"dry_run": dry_run(scans, out), "coverage": cov}
    else:
        if not coverage_ok(cov):
            raise SystemExit("some targets fail the stat check; refusing to scan")
        body = {"scan_results": full_run(scans, tgts, out), "coverage": cov}
    common.write_json(
        out / "run.json",
        common.run_record(
            "stage1",
            run_id,
            started,
            hashes,
            {
                "mode": "dry-run" if args.dry_run else "scan",
                "scans": scans,
                "limit": args.limit,
                "split": "F_dev",
                "dataset_root": "env:ISB_DATA",
                "out_dir": common.rel_to_root(out),
                **body,
            },
        ),
    )
    log(f"run {run_id} -> {common.rel_to_root(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

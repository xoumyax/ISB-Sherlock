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
from collections.abc import Callable
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


def full_run(
    scans: list[str],
    tgts: dict[str, list],
    out: Path,
    on_scan_done: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
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
        if on_scan_done:
            on_scan_done(name, done[name])
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


def hash_seed_ok() -> bool:
    return sys.flags.hash_randomization == 0


class RunRecord:
    """run.json, rewritten atomically at start, after each scan, and at the end."""

    def __init__(self, out: Path, run_id: str, fields: dict[str, Any]) -> None:
        self.path = out / "run.json"
        self.run_id = run_id
        self.started = common.utc_now()
        self.inputs: dict[str, str] = {}
        self.fields = {"status": "running", "scans_done": [], **fields}
        self.save()

    def update(self, **fields: Any) -> None:
        self.fields.update(fields)
        self.save()

    def save(self) -> None:
        rec = common.run_record(
            "stage1", self.run_id, self.started, self.inputs, self.fields
        )
        common.write_json_atomic(self.path, rec)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not hash_seed_ok():
        raise SystemExit(
            "PYTHONHASHSEED=0 is required (and python -I ignores it; use -P -s)"
        )
    run_id = args.run_id or common.new_run_id()
    out = common.check_output_dir(args.out_dir or common.RUNS_DIR / "stage1" / run_id)
    scans = list(SCAN_ORDER) if args.scan == "all" else [args.scan]
    out.mkdir(parents=True, exist_ok=True)
    rec = RunRecord(
        out,
        run_id,
        {
            "mode": "dry-run" if args.dry_run else "scan",
            "scans": scans,
            "limit": args.limit,
            "split": "F_dev",
            "dataset_root": "env:ISB_DATA",
            "out_dir": common.rel_to_root(out),
        },
    )
    try:
        rec.inputs = common.verified_inputs(input_rels(scans))
        tgts, cov = load_targets(args.limit)
        log(f"targets {cov['selected']}; stat {cov['stat']}")
        rec.update(coverage=cov)
        if args.dry_run:
            rec.update(dry_run=dry_run(scans, out))
        else:
            if not coverage_ok(cov):
                raise SystemExit("some targets fail the stat check; refusing to scan")
            results: dict[str, Any] = {}

            def done(name: str, summary: dict[str, Any]) -> None:
                results[name] = summary
                rec.update(
                    scans_done=[*rec.fields["scans_done"], name],
                    scan_results=dict(results),
                )

            full_run(scans, tgts, out, on_scan_done=done)
    except BaseException as exc:
        rec.update(status="failed", error=type(exc).__name__, message=str(exc)[:300])
        raise
    rec.update(status="complete")
    log(f"run {run_id} -> {common.rel_to_root(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

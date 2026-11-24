"""Stage 0: re-aggregate V1's stored detection.json files into its headline tables.

Every number is recomputed from the stored per-unit integers (``tp``,
``n_held_family``, ``benign_match``, ``benign_by_source``, ``cross_match``),
not copied from V1's stored ``grid``; the grid is used only as a cross-check.
Acceptance (REPRO_PLAN §f): each reported number equals the recomputed one at
the report's printed precision, compared as formatted strings.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

BUDGETED_ARMS = ("prevalence_k", "random_k", "learned", "analyst")
SOURCES = ("static", "classifier", "union")

#: R1, report tab:ladder: (source, arm) -> (TPR, FP/1k, Win8 FP/1k, cross-fam).
R1_EXPECTED: dict[tuple[str, str], tuple[str, str, str, str]] = {
    ("classifier", "all"): ("0.567", "333.32", "333.39", "891"),
    ("union", "prevalence_k"): ("0.351", "0.64", "1.45", "49"),
    ("classifier", "lint"): ("0.337", "0.12", "0.06", "24"),
    ("classifier", "prevalence_k"): ("0.337", "0.12", "0.06", "24"),
    ("classifier", "random_k"): ("0.337", "0.17", "0.00", "24"),
    ("classifier", "learned"): ("0.303", "0.15", "0.00", "24"),
    ("classifier", "analyst"): ("0.299", "0.07", "0.06", "23"),
    ("union", "analyst"): ("0.261", "0.37", "0.41", "40"),
    ("static", "prevalence_k"): ("0.249", "0.64", "1.51", "47"),
    ("static", "analyst"): ("0.201", "0.17", "0.29", "29"),
    ("union", "learned"): ("0.180", "0.27", "0.23", "28"),
    ("static", "learned"): ("0.138", "0.17", "0.23", "23"),
    ("static", "random_k"): ("0.054", "0.00", "0.00", "17"),
    ("union", "random_k"): ("0.050", "0.00", "0.00", "17"),
}
#: R2, report §res:ladder.
R2_EXPECTED = {
    "units": "108",
    "compiled": "84",
    "unrenderable": "24",
    "largest_n_strings": "412124",
}
#: R4, report tab:yargen: arm -> (TPR, FP/1k, Win8 FP/1k).
R4_EXPECTED = {
    "yargen_stock": ("0.747", "253.85", "72.26"),
    "yargen_gstats": ("0.634", "107.27", "59.12"),
}
#: R4 text: rule counts and the headline ratios.
R4_TEXT_EXPECTED = {
    "yargen_rules_total": "1755",
    "rules_per_family": "146",
    "tpr_ratio_vs_union_prev_k": "2.13",
    "fp_ratio_vs_union_prev_k": "399",
    "fp_ratio_vs_classifier_prev_k": "2164",
}
#: R7, report tab:gen (planformat, budgeted): name -> (generator key, style,
#: TPR, FP/1k, compile errors over the 72 budgeted units).
R7_EXPECTED: dict[str, tuple[str, str, str, str, str]] = {
    "llama_taskmix": ("llama_taskmix", "planformat", "0.236", "0.23", "0"),
    "ministral": ("ministral", "planformat", "0.234", "0.24", "7"),
    "bart_scooper": ("bart_scooper", "planformat", "0.231", "0.20", "5"),
    "t5gemma_humanized": ("t5gemma_humanized", "planformat", "0.227", "0.23", "0"),
    "lfm2_consistency": ("lfm2_consistency", "planformat", "0.430", "193.27", "10"),
    "bart": ("bart", "planformat", "0.239", "0.31", "1"),
    "bart_taskmix_base": ("bart_taskmix_base", "planformat", "0.225", "0.58", "2"),
    "codet5p_consistency": ("codet5p_consistency", "planformat", "0.208", "0.26", "3"),
    "bart_taskmix_human": ("bart_taskmix_human", "planformat", "0.207", "0.78", "8"),
    "bart_humanized": ("bart_humanized", "planformat", "0.241", "11.46", "5"),
    "llama1b_consistency": (
        "llama1b_consistency_step25934",
        "planformat",
        "0.222",
        "0.09",
        "32",
    ),
    "template": ("template", "describer", "0.230", "0.23", "0"),
}
#: Beside V1's definition (decision 4): the pooled per-unit mean, from REPRO_PLAN.
R7_POOLED_EXPECTED = {"lfm2_consistency": "209.90"}
#: llama1b footnote: its FP/1k comes from 40 scanned units.
R7_LLAMA1B_SCANNED = "40"

_YAR_RULE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+", re.M)


#: What a check's expected value is. Only "report" checks count as reproduced.
KINDS = {
    "report": "report",
    "derived": "derived from a report number",
    "internal": "internal (not from the report)",
}


def check(
    expected: str, got: float | int, decimals: int | None, kind: str = "report"
) -> dict[str, Any]:
    """One comparison at printed precision; ``decimals=None`` means an integer.

    ``kind``: "report" (a number printed in V1's report), "derived" (computed
    from a report number, e.g. a per-family average of a reported total), or
    "internal" (our own number against our own number: a consistency check,
    never counted as reproduced).
    """
    shown = str(int(got)) if decimals is None else f"{got:.{decimals}f}"
    return {
        "expected": expected,
        "got": shown,
        "raw": got,
        "pass": shown == expected,
        "kind": KINDS[kind],
    }


def cell_stats(
    units: Iterable[Mapping[str, Any]], n_goodware: int, win8_count: int
) -> dict[str, Any]:
    """Recompute V1's grid cell from per-unit integers."""
    units = list(units)
    n = len(units)
    tp = sum(u["tp"] for u in units)
    held = sum(u["n_held_family"] for u in units)
    fps = [1000.0 * u["benign_match"] / n_goodware for u in units]
    win8 = sum((u.get("benign_by_source") or {}).get("Win8", 0) for u in units)
    return {
        "n": n,
        "tp": tp,
        "held": held,
        "tpr": tp / max(1, held),
        "fp_per_1k": sum(fps) / n if n else 0.0,
        "win8_fp_per_1k": round(1000.0 * win8 / max(1, win8_count * n), 2),
        "cross": sum(u["cross_match"] for u in units),
        "benign_hits": sum(u["benign_match"] for u in units),
    }


def group_cells(det: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    cells: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for u in det["per_unit"].values():
        cells[f"{u['candidate_source']}__{u['arm']}"].append(u)
    return cells


def r1_ladder(det_m4: Mapping[str, Any]) -> dict[str, Any]:
    n_good = det_m4["n_goodware"]
    win8 = det_m4["goodware_by_source"]["Win8"]
    cells = group_cells(det_m4)
    rows = {}
    for (src, arm), (e_tpr, e_fp, e_w8, e_cross) in R1_EXPECTED.items():
        key = f"{src}__{arm}"
        s = cell_stats(cells[key], n_good, win8)
        rows[key] = {
            "n_units": s["n"],
            "tpr": check(e_tpr, s["tpr"], 3),
            "fp_per_1k": check(e_fp, s["fp_per_1k"], 2),
            "win8_fp_per_1k": check(e_w8, s["win8_fp_per_1k"], 2),
            "cross_fam": check(e_cross, s["cross"], None),
            "stored_grid_agrees": _grid_agrees(det_m4["grid"].get(key), s),
        }
    return rows


def _grid_agrees(stored: Mapping[str, Any] | None, s: Mapping[str, Any]) -> bool:
    if not stored:
        return False
    return (
        stored["n"] == s["n"]
        and stored["tp"] == s["tp"]
        and stored["cross"] == s["cross"]
        and abs(stored["fp_per_1k"] - s["fp_per_1k"]) < 1e-9
    )


def r2_renderability(det_m4: Mapping[str, Any]) -> dict[str, Any]:
    unrender = det_m4["unrenderable"]
    n_units = len(det_m4["per_unit"]) + len(det_m4["compile_errors"])
    largest = max(v["n_strings"] for v in unrender.values())
    return {
        "units": check(R2_EXPECTED["units"], n_units, None),
        "compiled": check(R2_EXPECTED["compiled"], len(det_m4["per_unit"]), None),
        "unrenderable": check(R2_EXPECTED["unrenderable"], len(unrender), None),
        "largest_n_strings": check(R2_EXPECTED["largest_n_strings"], largest, None),
    }


def count_yargen_rules(yar_dir: Path) -> dict[str, int]:
    """Rules per ``<variant>/<family>.yar``, counted by regex over the text."""
    counts = {}
    for path in sorted(yar_dir.glob("*/*.yar")):
        text = path.read_bytes().decode("utf-8", errors="replace")
        counts[f"{path.parent.name}/{path.stem}"] = len(_YAR_RULE.findall(text))
    return counts


def r4_yargen(
    det_y: Mapping[str, Any], det_m4: Mapping[str, Any], rule_counts: Mapping[str, int]
) -> dict[str, Any]:
    n_good, win8 = det_y["n_goodware"], det_y["goodware_by_source"]["Win8"]
    cells = group_cells(det_y)
    rows: dict[str, Any] = {}
    stats = {}
    for arm, (e_tpr, e_fp, e_w8) in R4_EXPECTED.items():
        s = cell_stats(cells[f"yargen__{arm}"], n_good, win8)
        stats[arm] = s
        rows[arm] = {
            "n_units": s["n"],
            "tpr": check(e_tpr, s["tpr"], 3),
            "fp_per_1k": check(e_fp, s["fp_per_1k"], 2),
            "win8_fp_per_1k": check(e_w8, s["win8_fp_per_1k"], 2),
        }
    m4 = group_cells(det_m4)
    m4_good, m4_w8 = det_m4["n_goodware"], det_m4["goodware_by_source"]["Win8"]
    union_pk = cell_stats(m4["union__prevalence_k"], m4_good, m4_w8)
    cls_pk = cell_stats(m4["classifier__prevalence_k"], m4_good, m4_w8)
    stock = stats["yargen_stock"]
    total = sum(rule_counts.values())
    e = R4_TEXT_EXPECTED
    rows["text"] = {
        "yargen_rules_total": check(e["yargen_rules_total"], total, None),
        "rules_per_family": check(
            e["rules_per_family"],
            round(total / max(1, len(rule_counts))),
            None,
            kind="derived",
        ),
        "tpr_ratio_vs_union_prev_k": check(
            e["tpr_ratio_vs_union_prev_k"], stock["tpr"] / union_pk["tpr"], 2
        ),
        "fp_ratio_vs_union_prev_k": check(
            e["fp_ratio_vs_union_prev_k"],
            round(stock["fp_per_1k"] / union_pk["fp_per_1k"]),
            None,
        ),
        "fp_ratio_vs_classifier_prev_k": check(
            e["fp_ratio_vs_classifier_prev_k"],
            round(stock["fp_per_1k"] / cls_pk["fp_per_1k"]),
            None,
        ),
    }
    return rows


def _split_uid(uid: str) -> tuple[str, str, str]:
    """``tag::source__arm__family[__gen]`` -> (tag, source, arm)."""
    tag, rest = uid.split("::", 1)
    source, arm = rest.split("__")[:2]
    return tag, source, arm


def generator_row(det: Mapping[str, Any], generator: str, style: str) -> dict[str, Any]:
    """One R7 row, by V1's definition plus the pooled view (decision 4)."""
    meta = det["unit_meta"]
    n_good = det["n_goodware"]
    budgeted = [
        uid
        for uid, m in meta.items()
        if m["generator"] == generator
        and m["prompt_style"] == style
        and _split_uid(uid)[2] in BUDGETED_ARMS
    ]
    compiled = [uid for uid in budgeted if uid in det["per_unit"]]
    errors = [uid for uid in budgeted if uid in det["compile_errors"]]
    cells: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for uid in compiled:
        _, src, arm = _split_uid(uid)
        cells[f"{src}__{arm}"].append(det["per_unit"][uid])
    win8 = det["goodware_by_source"]["Win8"]
    cell_fps = [cell_stats(us, n_good, win8)["fp_per_1k"] for us in cells.values()]
    pooled = cell_stats([det["per_unit"][u] for u in compiled], n_good, win8)
    return {
        "n_budgeted_units": len(budgeted),
        "n_compiled": len(compiled),
        "n_compile_errors": len(errors),
        "n_cells": len(cells),
        "tpr": pooled["tpr"],
        "fp_per_1k_cell_means": sum(cell_fps) / len(cell_fps) if cell_fps else 0.0,
        "fp_per_1k_pooled_units": pooled["fp_per_1k"],
        "benign_hits": pooled["benign_hits"],
    }


def r7_generators(det_all: Mapping[str, Any]) -> dict[str, Any]:
    rows = {}
    for name, (gen, style, e_tpr, e_fp, e_err) in R7_EXPECTED.items():
        r = generator_row(det_all, gen, style)
        row = {
            "prompt_style": style,
            "n_budgeted_units": r["n_budgeted_units"],
            "n_cells": r["n_cells"],
            "tpr": check(e_tpr, r["tpr"], 3),
            "fp_per_1k": check(e_fp, r["fp_per_1k_cell_means"], 2),
            "compile_errors": check(e_err, r["n_compile_errors"], None),
            "fp_per_1k_pooled_units": round(r["fp_per_1k_pooled_units"], 2),
            "benign_hits": r["benign_hits"],
        }
        if name in R7_POOLED_EXPECTED:
            row["fp_per_1k_pooled_check"] = check(
                R7_POOLED_EXPECTED[name],
                r["fp_per_1k_pooled_units"],
                2,
                kind="internal",
            )
        if name == "llama1b_consistency":
            row["n_scanned_units"] = check(R7_LLAMA1B_SCANNED, r["n_compiled"], None)
        rows[name] = row
    return rows


def iter_checks(obj: Any, path: str = "") -> Iterable[tuple[str, dict[str, Any]]]:
    """Every leaf ``check`` dict in a results tree, with its dotted path."""
    if isinstance(obj, dict):
        if {"expected", "got", "pass"} <= obj.keys():
            yield path, obj
            return
        for k, v in obj.items():
            yield from iter_checks(v, f"{path}.{k}" if path else str(k))


def aggregate(
    det_m4: Mapping[str, Any],
    det_y: Mapping[str, Any],
    det_all: Mapping[str, Any],
    rule_counts: Mapping[str, int],
) -> dict[str, Any]:
    results = {
        "R1": r1_ladder(det_m4),
        "R2": r2_renderability(det_m4),
        "R4": r4_yargen(det_y, det_m4, rule_counts),
        "R7": r7_generators(det_all),
    }
    results["summary"] = summarize(results)
    return results


def summarize(results: Mapping[str, Any]) -> dict[str, Any]:
    """Counts per kind; only "report" checks are reproduced numbers."""
    checks = list(iter_checks(results))
    out: dict[str, Any] = {}
    for short, label in KINDS.items():
        mine = [c for _, c in checks if c["kind"] == label]
        out[short] = {"n_checks": len(mine), "n_pass": sum(c["pass"] for c in mine)}
    out["failed"] = [p for p, c in checks if not c["pass"]]
    return out

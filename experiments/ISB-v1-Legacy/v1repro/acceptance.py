"""Stage 1 acceptance (REPRO_PLAN §f): exact integers against V1's detection.json.

Per unit: ``tp``, ``cross_match``, ``benign_match``, ``gen_match``,
``n_held_family`` and every ``benign_by_source`` count must be equal. The unit
sets and the compile-error sets must be equal both ways, the compile counts
must match the plan, and every ``failures`` dict must be empty (a timeout or a
missing file fails the scan). A ``--limit`` run is never an acceptance run.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

INT_FIELDS = ("tp", "cross_match", "benign_match", "gen_match", "n_held_family")

#: scan -> reference detection.json (relative to inputs/) and expected counts.
SCANS: dict[str, dict[str, Any]] = {
    "template": {
        "ref": "artifacts/exp2__m4/detection.json",
        "n_units": 108,
        "n_compiled": 84,
        "n_over_string_limit": 24,
        "n_compile_errors": 24,
    },
    "yargen": {
        "ref": "artifacts/yargen/detection.json",
        "n_units": 12,
        "n_compiled": 12,
        "n_over_string_limit": 0,
        "n_compile_errors": 0,
    },
    "generators": {
        "ref": "artifacts/exp2_all/detection.json",
        "n_units": 1956,
        "n_compiled": 1734,
        "n_over_string_limit": 24,
        "n_compile_errors": 222,
    },
}


def _nonzero(d: Mapping[str, int] | None) -> dict[str, int]:
    return {k: int(v) for k, v in (d or {}).items() if v}


def compare_compile(
    scan: str, summary: Mapping[str, Any], ref: Mapping[str, Any]
) -> list[str]:
    """Compile counts against the plan, and compile-error ids against V1's."""
    exp = SCANS[scan]
    bad = []
    got_counts = {
        "n_units": summary["n_units"],
        "n_compiled": summary["n_compiled"],
        "n_over_string_limit": summary["n_over_string_limit"],
        "n_compile_errors": len(summary["compile_errors"]),
    }
    for key, val in got_counts.items():
        if val != exp[key]:
            bad.append(f"{key}: expected {exp[key]}, got {val}")
    got_err, ref_err = set(summary["compile_errors"]), set(ref["compile_errors"])
    if got_err != ref_err:
        bad.append(
            f"compile-error ids differ: {len(got_err - ref_err)} new, "
            f"{len(ref_err - got_err)} missing"
        )
    return bad


def compare_units(got: Mapping[str, Any], ref: Mapping[str, Any]) -> list[str]:
    bad = []
    g_units, r_units = got["per_unit"], ref["per_unit"]
    only_got, only_ref = set(g_units) - set(r_units), set(r_units) - set(g_units)
    if only_got or only_ref:
        bad.append(f"unit sets differ: {len(only_got)} extra, {len(only_ref)} missing")
    for uid in sorted(set(g_units) & set(r_units)):
        g, r = g_units[uid], r_units[uid]
        for f in INT_FIELDS:
            if int(g[f]) != int(r[f]):
                bad.append(f"{uid}.{f}: expected {r[f]}, got {g[f]}")
        if _nonzero(g.get("benign_by_source")) != _nonzero(r.get("benign_by_source")):
            bad.append(
                f"{uid}.benign_by_source: expected "
                f"{_nonzero(r.get('benign_by_source'))}, "
                f"got {_nonzero(g.get('benign_by_source'))}"
            )
    return bad


def compare_failures(got: Mapping[str, Any]) -> list[str]:
    return [
        f"failures[{corpus}]: {dict(f)}"
        for corpus, f in (got.get("failures") or {}).items()
        if f
    ]


def compare_scan(
    scan: str, got: Mapping[str, Any], ref: Mapping[str, Any], limit: int | None = None
) -> dict[str, Any]:
    """Full Stage 1 comparison for one scan."""
    bad: list[str] = []
    if limit:
        bad.append(f"limited run (--limit {limit}) is not an acceptance run")
    bad += compare_compile(scan, got["compile"], ref)
    bad += compare_failures(got)
    if got.get("n_goodware") != ref.get("n_goodware"):
        bad.append(
            f"n_goodware: expected {ref.get('n_goodware')}, got {got.get('n_goodware')}"
        )
    if _nonzero(got.get("goodware_by_source")) != _nonzero(
        ref.get("goodware_by_source")
    ):
        bad.append("goodware_by_source differs")
    bad += compare_units(got, ref)
    return {
        "scan": scan,
        "pass": not bad,
        "n_mismatches": len(bad),
        "mismatches": bad[:200],
        "n_units_compared": len(got.get("per_unit", {})),
        "warnings": dict(got.get("warnings") or {}),
    }

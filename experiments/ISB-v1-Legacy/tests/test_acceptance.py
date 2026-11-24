from __future__ import annotations

import copy
from typing import Any

import pytest

from v1repro import acceptance, stage0


def unit(tp: int = 3, benign: dict[str, int] | None = None) -> dict[str, Any]:
    by_src = benign if benign is not None else {"Win8": 1}
    return {
        "family": "fa",
        "arm": "prevalence_k",
        "candidate_source": "yargen",
        "n_held_family": 10,
        "tp": tp,
        "cross_match": 1,
        "gen_match": 2,
        "benign_match": sum(by_src.values()),
        "benign_by_source": by_src,
    }


def ref_det() -> dict[str, Any]:
    per_unit = {
        f"yargen_{v}__f{i}": unit() for v in ("gstats", "stock") for i in range(6)
    }
    return {
        "per_unit": per_unit,
        "compile_errors": {},
        "n_goodware": 100,
        "goodware_by_source": {"Win8": 40, "UCSB": 60},
        "failures": {"held": {}, "goodware": {}, "gen": {}},
    }


def got_from(ref: dict[str, Any]) -> dict[str, Any]:
    got = copy.deepcopy(ref)
    got["compile"] = {
        "n_units": 12,
        "n_compiled": 12,
        "n_over_string_limit": 0,
        "compile_errors": {},
    }
    got["warnings"] = {"too_many_matches": 3}
    return got


def test_identical_passes() -> None:
    ref = ref_det()
    r = acceptance.compare_scan("yargen", got_from(ref), ref)
    assert r["pass"], r["mismatches"]
    assert r["warnings"] == {"too_many_matches": 3}


def test_zero_count_sources_are_equivalent() -> None:
    ref = ref_det()
    got = got_from(ref)
    got["per_unit"]["yargen_stock__f0"]["benign_by_source"]["UCSB"] = 0
    assert acceptance.compare_scan("yargen", got, ref)["pass"]


@pytest.mark.parametrize(
    "field", ["tp", "cross_match", "benign_match", "gen_match", "n_held_family"]
)
def test_integer_mismatch_fails(field: str) -> None:
    ref = ref_det()
    got = got_from(ref)
    got["per_unit"]["yargen_gstats__f2"][field] += 1
    r = acceptance.compare_scan("yargen", got, ref)
    assert not r["pass"]
    assert any(f"yargen_gstats__f2.{field}" in m for m in r["mismatches"])


def test_benign_by_source_mismatch_fails() -> None:
    ref = ref_det()
    got = got_from(ref)
    got["per_unit"]["yargen_gstats__f1"]["benign_by_source"] = {"UCSB": 1}
    assert not acceptance.compare_scan("yargen", got, ref)["pass"]


def test_unit_set_difference_fails() -> None:
    ref = ref_det()
    got = got_from(ref)
    del got["per_unit"]["yargen_stock__f5"]
    assert not acceptance.compare_scan("yargen", got, ref)["pass"]


@pytest.mark.parametrize("kind", ["timeout", "missing_file", "scan_error"])
def test_any_failure_fails(kind: str) -> None:
    ref = ref_det()
    got = got_from(ref)
    got["failures"]["goodware"] = {kind: 1}
    assert not acceptance.compare_scan("yargen", got, ref)["pass"]


def test_compile_count_and_ids_checked() -> None:
    ref = ref_det()
    got = got_from(ref)
    got["compile"]["n_compiled"] = 11
    got["compile"]["compile_errors"] = {"yargen_stock__f5": "SyntaxError"}
    r = acceptance.compare_scan("yargen", got, ref)
    assert not r["pass"]
    assert any("n_compiled" in m for m in r["mismatches"])
    assert any("compile-error ids" in m for m in r["mismatches"])


def test_limited_run_is_never_accepted() -> None:
    ref = ref_det()
    assert not acceptance.compare_scan("yargen", got_from(ref), ref, limit=5)["pass"]


def test_expected_plan_counts() -> None:
    s = acceptance.SCANS
    assert (s["template"]["n_compiled"], s["template"]["n_over_string_limit"]) == (
        84,
        24,
    )
    assert s["generators"]["n_units"] == 22 * 84 + 108 == 1956
    assert (s["generators"]["n_compiled"], s["generators"]["n_compile_errors"]) == (
        1734,
        222,
    )


def test_stage0_check_uses_printed_precision() -> None:
    assert stage0.check("0.337", 0.33716, 3)["pass"]
    assert not stage0.check("0.337", 0.3376, 3)["pass"]
    assert stage0.check("24", 24, None)["pass"]


def test_stage0_cell_fp_is_mean_of_unit_rates() -> None:
    us = [
        {
            "tp": 1,
            "n_held_family": 10,
            "benign_match": 0,
            "cross_match": 0,
            "benign_by_source": {},
        },
        {
            "tp": 3,
            "n_held_family": 10,
            "benign_match": 10,
            "cross_match": 2,
            "benign_by_source": {"Win8": 4},
        },
    ]
    s = stage0.cell_stats(us, n_goodware=1000, win8_count=100)
    assert s["tpr"] == pytest.approx(0.2)
    assert s["fp_per_1k"] == pytest.approx(5.0)
    assert s["win8_fp_per_1k"] == pytest.approx(20.0)
    assert s["cross"] == 2 and s["benign_hits"] == 10

"""Synthetic rules over synthetic files in tmp_path. Never real samples."""

from __future__ import annotations

from pathlib import Path

from v1repro import scan
from v1repro.targets import TargetSpec


def rule(name: str, text: str) -> str:
    return f'rule {name} {{ strings: $a = "{text}" condition: $a }}'


def unit(uid: str, family: str, text: str, n_strings: int | None = 1) -> dict:
    return {
        "unit_id": uid,
        "family": family,
        "arm": "prevalence_k",
        "source": rule("r", text),
        "candidate_source": "static",
        "meta": {"n_strings": n_strings},
    }


def make(
    tmp: Path,
    name: str,
    data: bytes,
    kind: str,
    family: str | None = None,
    source: str | None = None,
) -> TargetSpec:
    p = tmp / name
    p.write_bytes(data)
    return TargetSpec(
        sha256=name.ljust(64, "0"), path=str(p), kind=kind, family=family, source=source
    )


def corpora(tmp: Path) -> dict[str, list[TargetSpec]]:
    return {
        "held": [
            make(tmp, "h1", b"..ALPHA..", "held", "fa"),
            make(tmp, "h2", b"..ALPHA..BETA", "held", "fa"),
            make(tmp, "h3", b"..BETA..", "held", "fb"),
        ],
        "gen": [make(tmp, "g1", b"ALPHA", "gen", "fa")],
        "goodware": [
            make(tmp, "b1", b"benign ALPHA", "goodware", source="Win8"),
            make(tmp, "b2", b"benign BETA", "goodware", source="UCSB"),
            make(tmp, "b3", b"benign BETA", "goodware", source="Win8"),
            make(tmp, "b4", b"plain", "goodware", source="UCSB"),
        ],
    }


def test_synthetic_scan_counts(tmp_path: Path) -> None:
    units = [
        unit("u_alpha", "fa", "ALPHA"),
        unit("u_beta", "fa", "BETA"),
        unit("u_bad", "fb", 'oops" garbage'),
    ]
    res = scan.run_scan(units, corpora(tmp_path))
    a, b = res["per_unit"]["u_alpha"], res["per_unit"]["u_beta"]
    assert (a["tp"], a["cross_match"], a["gen_match"], a["benign_match"]) == (
        2,
        0,
        1,
        1,
    )
    assert a["benign_by_source"] == {"Win8": 1}
    # u_beta is a family-fa rule: h2 is its own TP, h3 (family fb) is cross-family.
    assert (b["tp"], b["cross_match"], b["gen_match"], b["benign_match"]) == (
        1,
        1,
        0,
        2,
    )
    assert b["benign_by_source"] == {"UCSB": 1, "Win8": 1}
    assert "u_bad" in res["compile_errors"] and "u_bad" not in res["per_unit"]
    assert res["compile"]["n_units"] == 3 and res["compile"]["n_compiled"] == 2
    assert res["failures"] == {"held": {}, "goodware": {}, "gen": {}}
    assert res["n_goodware"] == 4


def test_missing_file_is_a_failure(tmp_path: Path) -> None:
    c = corpora(tmp_path)
    c["goodware"].append(
        TargetSpec(
            sha256="z" * 64, path=str(tmp_path / "nope"), kind="goodware", source="UCSB"
        )
    )
    res = scan.run_scan([unit("u_alpha", "fa", "ALPHA")], c)
    assert res["failures"]["goodware"] == {"missing_file": 1}


def test_default_config_is_v1s() -> None:
    cfg = scan.load_harness().DetectionConfig()
    assert cfg.match_timeout == 30 and cfg.max_strings_per_rule == 10_000
    assert cfg.goodware_cap == 0


def test_too_many_matches_warning_is_counted_not_failed(tmp_path: Path) -> None:
    c = corpora(tmp_path)
    c["goodware"].append(
        make(tmp_path, "big", b"A" * 1_100_000, "goodware", source="UCSB")
    )
    res = scan.run_scan([unit("u_a", "fa", "AA")], c)
    assert res["warnings"].get("too_many_matches", 0) >= 1
    assert res["failures"]["goodware"] == {}
    assert res["per_unit"]["u_a"]["benign_match"] >= 1

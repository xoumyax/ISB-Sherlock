from __future__ import annotations

from pathlib import Path

import pytest

from v1repro import scan, units

YAR_WITH_NUL = (
    b"/* base64 encoded string '\x00\x00ab' */\n"
    b'rule r1 { strings: $a = "abc" condition: $a }\n'
    b'rule r2 { strings: $b = "de\xfffg" condition: $b }\n'
)


def test_yargen_source_escapes_nul_and_replaces_bad_utf8() -> None:
    src = units.yargen_source(YAR_WITH_NUL)
    assert "\x00" not in src
    assert "'\\x00\\x00ab'" in src
    assert "�" in src  # errors="replace"


def test_yargen_units_layout(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    (root / "gstats").mkdir(parents=True)
    (root / "stock").mkdir()
    (root / "gstats" / "fb.yar").write_bytes(YAR_WITH_NUL)
    (root / "gstats" / "fa.yar").write_bytes(YAR_WITH_NUL)
    (root / "gstats" / "notes.txt").write_bytes(b"x")
    (root / "stock" / "fa.yar").write_bytes(b"  \n")  # empty: skipped
    us = units.yargen_units(root)
    assert [u["unit_id"] for u in us] == ["yargen_gstats__fa", "yargen_gstats__fb"]
    assert all(u["meta"] == {} and u["candidate_source"] == "yargen" for u in us)
    assert us[0]["arm"] == "yargen_gstats" and us[0]["family"] == "fa"


def test_yargen_unit_compiles_through_harness(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    (root / "stock").mkdir(parents=True)
    (root / "stock" / "fa.yar").write_bytes(YAR_WITH_NUL)
    _h, summary = scan.compile_units(units.yargen_units(root))
    assert summary["n_compiled"] == 1 and not summary["compile_errors"]


def test_without_n_strings_harness_counts_by_regex() -> None:
    body = "\n".join(f'    $s{i} = "x{i}"' for i in range(10_001))
    src = f"rule big {{\n  strings:\n{body}\n  condition: any of them\n}}\n"
    u = {
        "unit_id": "yargen_stock__big",
        "family": "f",
        "arm": "yargen_stock",
        "source": src,
        "candidate_source": "yargen",
        "meta": {},
    }
    _h, summary = scan.compile_units([u])
    assert summary["n_over_string_limit"] == 1
    assert "too_many_strings: 10001" in summary["compile_errors"]["yargen_stock__big"]


def test_meta_n_strings_is_trusted_for_template_units() -> None:
    rules = {
        "static__all__f": {
            "family": "f",
            "arm": "all",
            "candidate_source": "static",
            "source_text": 'rule a { strings: $a = "q" condition: $a }',
            "n_strings": 20_000,
            "over_string_limit": True,
        }
    }
    us = units.template_units(rules)
    assert us[0]["meta"] == {"n_strings": 20_000}
    _h, summary = scan.compile_units(us)
    assert summary["n_over_string_limit"] == 1 and summary["n_compiled"] == 0
    assert units.unrenderable(rules)["static__all__f"]["n_strings"] == 20_000


def test_generator_units_skip_empty_and_tag_ids() -> None:
    rules = {
        "static__prevalence_k__f__bart": {
            "family": "f",
            "arm": "prevalence_k",
            "candidate_source": "static",
            "source_text": "rule a { condition: true }",
            "generator": "bart",
            "n_strings": 0,
        },
        "static__all__f": {
            "family": "f",
            "arm": "all",
            "candidate_source": "static",
            "source_text": "  ",
        },
    }
    us = units.generator_units("bart_planformat", rules)
    assert [u["unit_id"] for u in us] == [
        "bart_planformat::static__prevalence_k__f__bart"
    ]
    assert us[0]["meta"]["prompt_style"] == "planformat"
    assert us[0]["meta"]["n_strings"] == 0


def test_pinned_tags() -> None:
    tags = units.GENERATOR_TAGS
    assert len(tags) == 23 and len(set(tags)) == 23
    assert list(tags) == sorted(tags)
    assert "m4" in tags and not any("smoke" in t for t in tags)
    assert units.prompt_style("m4") == "describer"
    with pytest.raises(ValueError):
        units.prompt_style("smoke")

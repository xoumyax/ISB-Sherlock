"""Rule units for the three V1 scans, built exactly as V1's drivers built them.

* template (``run_exp2.stage_score``): every unit of ``exp2__m4/rules.json``,
  bare unit id, ``meta n_strings``; no empty-source filter. 108 units.
* generators (``score_all.py``): the 23 pinned tags, unit id ``<tag>::<uid>``,
  units with an empty ``source_text`` skipped, ``meta n_strings``. 1,956 units.
* yarGen (``yargen_baseline.stage_score``): one unit per variant x family,
  the whole ``.yar`` decoded utf-8 with ``errors="replace"``, NUL -> ``\\x00``,
  empty sources skipped, no ``n_strings`` (the harness counts by regex). 12 units.

Units are returned as plain dicts; ``to_rule_units`` turns them into the
harness's ``RuleUnit``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

#: The 23 tags of job 95929, in its (sorted) order. Pinned: never globbed, so
#: ``smoke`` cannot enter. ``m4`` is the template (describer); the other 22
#: carry their prompt style as a suffix.
GENERATOR_TAGS: tuple[str, ...] = (
    "bart_describer",
    "bart_humanized_describer",
    "bart_humanized_planformat",
    "bart_planformat",
    "bart_scooper_describer",
    "bart_scooper_planformat",
    "bart_taskmix_base_describer",
    "bart_taskmix_base_planformat",
    "bart_taskmix_human_describer",
    "bart_taskmix_human_planformat",
    "codet5p_consistency_describer",
    "codet5p_consistency_planformat",
    "lfm2_consistency_describer",
    "lfm2_consistency_planformat",
    "llama1b_consistency_step25934_describer",
    "llama1b_consistency_step25934_planformat",
    "llama_taskmix_describer",
    "llama_taskmix_planformat",
    "m4",
    "ministral_describer",
    "ministral_planformat",
    "t5gemma_humanized_describer",
    "t5gemma_humanized_planformat",
)
TEMPLATE_TAG = "m4"
YARGEN_VARIANTS: tuple[str, ...] = ("gstats", "stock")


def rules_rel(tag: str) -> str:
    return f"artifacts/exp2__{tag}/rules.json"


def prompt_style(tag: str) -> str:
    """Never guess (score_all ``_style``): suffix, or the pinned m4 entry."""
    for style in ("describer", "planformat"):
        if tag.endswith("_" + style):
            return style
    if tag == TEMPLATE_TAG:
        return "describer"
    raise ValueError(f"no prompt style for tag {tag!r}")


def template_units(rules: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "unit_id": uid,
            "family": b["family"],
            "arm": b["arm"],
            "source": b["source_text"],
            "candidate_source": b["candidate_source"],
            "meta": {"n_strings": b.get("n_strings")},
        }
        for uid, b in rules.items()
    ]


def unrenderable(rules: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        uid: {
            "n_strings": b["n_strings"],
            "arm": b["arm"],
            "candidate_source": b["candidate_source"],
            "family": b["family"],
        }
        for uid, b in rules.items()
        if b.get("over_string_limit")
    }


def generator_units(
    tag: str, rules: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    style = prompt_style(tag)
    out = []
    for uid, b in rules.items():
        if not (b.get("source_text") or "").strip():
            continue
        gen = b.get("generator", "template")
        out.append(
            {
                "unit_id": f"{tag}::{uid}",
                "family": b["family"],
                "arm": b["arm"],
                "source": b["source_text"],
                "candidate_source": b["candidate_source"],
                "meta": {
                    "n_strings": b.get("n_strings"),
                    "generator": gen,
                    "prompt_style": style,
                    "tag": tag,
                },
            }
        )
    return out


def yargen_source(raw: bytes) -> str:
    """V1's preprocessing of a ``.yar`` file for ``yara.compile(source=...)``."""
    return raw.decode("utf-8", errors="replace").replace("\x00", "\\x00")


def yargen_units(rules_root: Path) -> list[dict[str, Any]]:
    """``rules_root/<variant>/<family>.yar`` -> one unit per variant x family."""
    out = []
    for variant in YARGEN_VARIANTS:
        vdir = rules_root / variant
        if not vdir.is_dir():
            continue
        for fname in sorted(p.name for p in vdir.iterdir()):
            if not fname.endswith(".yar"):
                continue
            source = yargen_source((vdir / fname).read_bytes())
            if not source.strip():
                continue
            fam = fname[:-4]
            out.append(
                {
                    "unit_id": f"yargen_{variant}__{fam}",
                    "family": fam,
                    "arm": f"yargen_{variant}",
                    "source": source,
                    "candidate_source": "yargen",
                    "meta": {},
                }
            )
    return out


def to_rule_units(units: Iterable[Mapping[str, Any]], rule_unit_cls: type) -> list:
    return [
        rule_unit_cls(
            unit_id=u["unit_id"],
            family=u["family"],
            arm=u["arm"],
            source=u["source"],
            candidate_source=u["candidate_source"],
            meta=dict(u["meta"]),
        )
        for u in units
    ]

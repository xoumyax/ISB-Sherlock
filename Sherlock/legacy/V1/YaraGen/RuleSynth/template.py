"""Deterministic renderer: ISB selection + condition plan -> YARA source.

This is the ``template`` generator of EXP2_DESIGN §9 -- the no-LM baseline. It
exists so that a TPR or FP difference between arms can be attributed to
*selection*, which is the thing under test. A language model in that position
would add its own variance to every cell and make the ablation unreadable.

Two properties it must have, and that its tests pin:

* **Every rule it emits compiles.** Candidates are filtered through the grammar
  before rendering, and a candidate that slips through raises rather than
  producing a rule that fails at scan time and silently scores zero.
* **The condition is exactly ISB-B's plan.** No extra terms, no ``any of them``
  fallback. If the plan is empty the rule says ``false`` -- an honest dead rule
  that scores zero TPR and zero FP, rather than a rule that matches everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from ..ISB.candidate import Candidate
from ..ISB.condition import ConditionBrain, ConditionPlan
from ..ISB.grammar import (
    DEFAULT_CONFIG,
    GrammarConfig,
    filter_expressible,
    render_module_term,
    render_string,
    required_modules,
    safe_identifier,
    sanitize_rule_name,
)

__all__ = ["RenderedRule", "render_template_rule", "YARA_MAX_STRINGS"]

#: Hard limit in libyara (``too many strings in rule``).
YARA_MAX_STRINGS = 10_000


@dataclass
class RenderedRule:
    """The rule text plus everything a scorer needs to interpret a match."""

    name: str
    source: str
    family: str
    arm: str
    n_strong: int = 0
    n_weak: int = 0
    n_module_terms: int = 0
    n_of: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    is_dead: bool = False
    #: YARA refuses more than 10,000 strings in one rule. The unbudgeted arms
    #: (`all`, `lint`) routinely exceed it by an order of magnitude, so "no
    #: selection" is not merely a weak rule -- it is not a rule at all. Flagged
    #: here so the ablation table can say that rather than showing a bare
    #: compile error.
    n_strings: int = 0
    over_string_limit: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name, "family": self.family, "arm": self.arm,
            "n_strong": self.n_strong, "n_weak": self.n_weak,
            "n_module_terms": self.n_module_terms, "n_of": self.n_of,
            "is_dead": self.is_dead, "dropped": self.dropped,
            "n_strings": self.n_strings,
            "over_string_limit": self.over_string_limit,
            "n_bytes": len(self.source),
        }


def render_template_rule(
    family: str,
    selected: Sequence[Candidate],
    arm: str = "template",
    brain: ConditionBrain | None = None,
    plan: ConditionPlan | None = None,
    config: GrammarConfig = DEFAULT_CONFIG,
    rule_name: str | None = None,
) -> RenderedRule:
    """Render one family's selection into YARA source.

    ``plan`` may be supplied when the caller already computed it (the driver
    does, to report condition shape per arm); otherwise ``brain`` builds one.
    """
    brain = brain or ConditionBrain()
    name = sanitize_rule_name(rule_name or f"ISB_{arm}_{family}")

    kept, dropped_map = filter_expressible(selected, config=config)
    dropped = {k: len(v) for k, v in dropped_map.items()}
    if plan is None:
        plan = brain.plan(family, kept)
    else:
        keep = {c.key() for c in kept}
        plan = ConditionPlan(
            family=plan.family,
            strong=[c for c in plan.strong if c.key() in keep],
            weak=[c for c in plan.weak if c.key() in keep],
            module_terms=[c for c in plan.module_terms if c.key() in keep],
            reasons=plan.reasons,
            n_weak_required=plan.n_weak_required,
        )

    strings: list[str] = []
    strong_ids: list[str] = []
    weak_ids: list[str] = []
    used: set[str] = set()

    def _ident(prefix: str, i: int) -> str:
        ident = safe_identifier(prefix, i)
        # Collisions would make the rule reference the wrong string; suffix
        # until unique rather than emitting a duplicate definition.
        while ident in used:
            i += 1
            ident = safe_identifier(prefix, i)
        used.add(ident)
        return ident

    for i, cand in enumerate(plan.strong):
        ident = _ident("s", i)
        strings.append("        " + render_string(cand, ident, config))
        strong_ids.append(ident)
    for i, cand in enumerate(plan.weak):
        ident = _ident("w", i)
        strings.append("        " + render_string(cand, ident, config))
        weak_ids.append(ident)

    module_terms = [render_module_term(c, config) for c in plan.module_terms]
    condition = brain.render_condition(plan, strong_ids, weak_ids, module_terms)
    is_dead = condition == "false"

    mods = required_modules(plan.module_terms)
    lines: list[str] = [f'import "{m}"' for m in mods]
    if lines:
        lines.append("")
    lines.append(f"rule {name}")
    lines.append("{")
    lines.append("    meta:")
    lines.append(f'        family = "{family}"')
    lines.append(f'        arm = "{arm}"')
    lines.append(f'        generator = "template"')
    if strings:
        lines.append("    strings:")
        lines.extend(strings)
    lines.append("    condition:")
    lines.append(f"        {condition}")
    lines.append("}")

    return RenderedRule(
        name=name, source="\n".join(lines) + "\n", family=family, arm=arm,
        n_strong=len(plan.strong), n_weak=len(plan.weak),
        n_module_terms=len(plan.module_terms), n_of=plan.n_of,
        dropped=dropped, is_dead=is_dead, n_strings=len(strings),
        over_string_limit=len(strings) > YARA_MAX_STRINGS)

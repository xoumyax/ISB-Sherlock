"""ISB-B, the Condition Brain: what shape should the rule's condition take?

Selection decides *which* candidates go in. This decides how they combine, and
that choice is where false positives are won or lost. The rule is::

    (module terms OR'd)          # hashes / imphash -- exact, always safe to OR
    or (any of ($strong*))       # specific enough to fire alone
    or (N of ($weak*))           # N = min(2, #weak)

**Never ``any of them``.** A gold rule built from one real report once matched
5/5 malware *and* 5/5 goodware under a permissive OR, because a single generic
string was enough to fire it. The threshold shape prevents the worst failure
structurally rather than hoping the selection stage filtered perfectly; the FP
column then measures what is left. This shape is brownie's call (2026-08-07) and
deliberately revises the earlier OR-merge spec.

**Strong vs weak is specificity, not rank.** A candidate fires alone iff it is a
hex pattern with >= 8 fixed bytes, or a literal of length >= 16 that no G_stats
goodware document carries. Notice both halves need the goodware oracle: with no
index every literal looks absent-from-goodware and everything is promoted to
strong, which quietly restores the ``any of them`` behaviour this module exists
to prevent. :class:`ConditionBrain` therefore refuses to promote on absence it
could not verify.

v1 is rule-based. The interface takes per-family ``n_weak`` and thresholds so a
learned version (tuned on F_dev, never F_test) can replace the constants without
changing any caller.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .candidate import Candidate
from .goodware import GoodwareOracle
from .grammar import render_kind

__all__ = ["ConditionConfig", "ConditionPlan", "ConditionBrain"]


@dataclass(frozen=True)
class ConditionConfig:
    """Thresholds for strong/weak classification and the N-of group."""

    #: Hex spans with at least this many fixed bytes fire alone.
    strong_hex_fixed_bytes: int = 8
    #: Literals at least this long AND absent from goodware fire alone.
    strong_literal_len: int = 16
    #: N in "N of ($weak*)", capped by how many weak strings exist.
    n_weak: int = 2
    #: Promote a literal to strong on goodware-absence only when an index
    #: actually scored it. Turning this off restores the pre-wipe FP behaviour.
    require_verified_absence: bool = True


@dataclass
class ConditionPlan:
    """The decided shape, ready for rendering or for a generator prompt."""

    family: str
    strong: list[Candidate] = field(default_factory=list)
    weak: list[Candidate] = field(default_factory=list)
    module_terms: list[Candidate] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)
    #: The configured N, before it is capped by how many weak strings exist.
    n_weak_required: int = 2

    @property
    def n_of(self) -> int:
        """N for the weak group -- never more than the group can satisfy.

        A lone weak string gives N=1, i.e. it fires alone. Intended: there is no
        threshold to form from one candidate, and demanding 2-of would make the
        group unsatisfiable and silently delete it from the rule.
        """
        if not self.weak:
            return 0
        return min(self.n_weak_required, len(self.weak))

    def is_empty(self) -> bool:
        return not (self.strong or self.weak or self.module_terms)

    def summary(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "n_strong": len(self.strong), "n_weak": len(self.weak),
            "n_module_terms": len(self.module_terms),
            "n_of": self.n_of,
            "fires_on_single_weak": bool(self.weak) and self.n_of == 1,
        }


class ConditionBrain:
    """Classifies candidates into strong / weak / module terms."""

    def __init__(
        self,
        oracle: GoodwareOracle | None = None,
        config: ConditionConfig | None = None,
    ):
        self.oracle = oracle or GoodwareOracle()
        self.config = config or ConditionConfig()

    # -- classification ------------------------------------------------
    def fixed_byte_count(self, hex_body: str) -> int:
        """Fixed bytes only. Wildcards and jumps carry no identity, so a span
        that is mostly ``??`` around two real bytes is not saved by its length."""
        return sum(
            1 for t in hex_body.split()
            if len(t) == 2 and "?" not in t and not t.startswith("~")
        )

    def is_strong(self, cand: Candidate) -> tuple[bool, str]:
        cfg = self.config
        if cand.is_hex:
            n = self.fixed_byte_count(cand.value)
            if n >= cfg.strong_hex_fixed_bytes:
                return True, f"hex_fixed_bytes:{n}"
            return False, f"hex_too_short:{n}"

        if cand.printable_len < cfg.strong_literal_len:
            return False, f"literal_short:{cand.printable_len}"

        verdict = self.oracle.verdict(cand)
        if verdict.index == "none":
            if cfg.require_verified_absence:
                # Unscored is not clean. Demote to weak rather than promote on
                # a lookup that never happened.
                return False, "absence_unverified"
            return True, "literal_long_unverified"
        if verdict.absent:
            return True, f"literal_long_goodware_absent:{cand.printable_len}"
        return False, f"goodware_df:{verdict.count}"

    def plan(
        self,
        family: str,
        selected: Sequence[Candidate],
    ) -> ConditionPlan:
        """Split a selection into the three condition groups."""
        out = ConditionPlan(family=family, n_weak_required=self.config.n_weak)
        for cand in selected:
            kind = render_kind(cand.ctype)
            if kind == "module":
                out.module_terms.append(cand)
                out.reasons[cand.norm] = "module_term"
                continue
            if kind == "none":
                out.reasons[cand.norm] = "not_renderable"
                continue
            strong, why = self.is_strong(cand)
            (out.strong if strong else out.weak).append(cand)
            out.reasons[cand.norm] = why
        return out

    # -- rendering -----------------------------------------------------
    def render_condition(
        self,
        plan: ConditionPlan,
        strong_ids: Sequence[str],
        weak_ids: Sequence[str],
        module_terms: Sequence[str] = (),
    ) -> str:
        """Render the condition text from already-assigned identifiers.

        Identifier assignment belongs to the rule writer (it has to match the
        strings section), so this takes ids rather than inventing them.
        """
        parts: list[str] = []
        if module_terms:
            parts.append("(" + " or ".join(module_terms) + ")")
        if strong_ids:
            parts.append("any of (" + ", ".join(strong_ids) + ")")
        if weak_ids:
            n = min(self.config.n_weak, len(weak_ids))
            # A lone weak string yields "1 of (...)", i.e. it fires alone. That
            # is intended: with one weak candidate there is no threshold to
            # form, and demanding 2-of would make the rule unsatisfiable.
            parts.append(f"{n} of (" + ", ".join(weak_ids) + ")")
        if not parts:
            return "false"        # explicit dead rule beats an empty condition
        return "\n        or ".join(parts)

    def prompt_terms(self, plan: ConditionPlan) -> dict[str, Any]:
        """Condition semantics for the generator prompt (EXP2_DESIGN §8).

        Strong terms are OR-joined, weak terms travel as an N-of group, so the
        LM is told the *shape* rather than left to invent one.
        """
        return {
            "family": plan.family,
            "module_terms": [c.value for c in plan.module_terms],
            "strong": [c.value for c in plan.strong],
            "weak": [c.value for c in plan.weak],
            "n_of": plan.n_of,
            "shape": "(modules OR) or (any of strong) or (N of weak)",
        }

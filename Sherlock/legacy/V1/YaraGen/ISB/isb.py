"""The ISB orchestrator: one family's pooled candidates -> a selection.

The arms are a **ladder**, not a menu (EXP2_DESIGN §9). Each rung answers "is the
next rung's extra machinery worth anything?":

===============  ==============================================================
``all``          no selection at all -- the honest reference. Only expressible.
``lint``         hygiene only: stoplist + goodware genericity. No ranking.
``prevalence_k`` the yarGen-shaped heuristic. **The bar the learned arm must
                 clear** -- beating random is not a result.
``random_k``     post-lint random draw, size-matched to ``learned``.
``learned``      ISB-A scorer + type_cover budget.
``analyst``      the secondary mining arm: PU-bagging over values a human
                 analyst put in a crawled rule. Family-AGNOSTIC -- crawled rule
                 names are anonymised, see ISB/mining.py.
``oracle_peek``  peeks at held-set truth. Upper bound only, flagged as cheating
                 in the output metadata so it can never be quoted as a result.
===============  ==============================================================

Two ordering constraints are structural, not stylistic:

* ``lint`` runs *after* emission, never folded into it. Folding hygiene into
  emission would make ``all`` a dishonest reference -- it is supposed to show
  what happens with no selection, including the bad parts.
* ``random_k`` is drawn **post-lint and size-matched to ``learned``**, which
  means ``learned`` must run first. A random arm drawn from a different pool or
  at a different size is not a control, it is a different experiment.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from .budget import BudgetConfig, apply_budget
from .candidate import Candidate
from .goodware import GoodwareOracle
from .grammar import DEFAULT_CONFIG, GrammarConfig, filter_expressible
from .pooling import PooledCandidate
from .salience import PriorScorer, SalienceScorer
from .stoplist import Stoplist

__all__ = ["ARMS", "ISBConfig", "Selection", "ISB"]

ARMS = ("all", "lint", "prevalence_k", "random_k", "learned", "analyst",
        "oracle_peek")

#: Arms that look at material the deployment path would not have.
PEEKING_ARMS = frozenset({"oracle_peek"})


@dataclass(frozen=True)
class ISBConfig:
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    grammar: GrammarConfig = DEFAULT_CONFIG
    #: Goodware DF at or above which lint calls a candidate generic.
    lint_max_goodware_df: int = 0
    seed: int = 20260809


@dataclass
class Selection:
    """What one arm selected for one family, and how it got there."""

    family: str
    arm: str
    selected: list[Candidate] = field(default_factory=list)
    dropped: dict[str, list[str]] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    peeked: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "family": self.family, "arm": self.arm,
            "n_selected": len(self.selected),
            "peeked": self.peeked,
            "dropped": {k: len(v) for k, v in self.dropped.items()},
            **self.stats,
        }


class ISB:
    """Runs the arm ladder over one family's pooled candidates."""

    def __init__(
        self,
        oracle: GoodwareOracle | None = None,
        scorer: SalienceScorer | None = None,
        stoplist: Stoplist | None = None,
        config: ISBConfig | None = None,
        analyst: Any | None = None,
    ):
        self.oracle = oracle or GoodwareOracle()
        self.scorer = scorer
        self.stoplist = stoplist or Stoplist()
        self.config = config or ISBConfig()
        #: PU-bagging scorer from ISB/mining.py. Without one the ladder skips
        #: the `analyst` arm rather than faking it with another scorer.
        self.analyst = analyst

    @property
    def analyst_available(self) -> bool:
        return self.analyst is not None

    # -- stages --------------------------------------------------------
    def expressible(
        self, pooled: Sequence[PooledCandidate]
    ) -> tuple[list[PooledCandidate], dict[str, list[str]]]:
        """Grammar filter. Applies to every arm including ``all``: a candidate
        YARA cannot express is not a selection choice, it is a non-option."""
        by_norm = {p.candidate.norm: p for p in pooled}
        kept, dropped = filter_expressible(
            [p.candidate for p in pooled], config=self.config.grammar)
        return ([by_norm[c.norm] for c in kept if c.norm in by_norm],
                {k: [c.value for c in v] for k, v in dropped.items()})

    def lint(
        self, pooled: Sequence[PooledCandidate]
    ) -> tuple[list[PooledCandidate], dict[str, list[str]]]:
        """Stoplist + goodware genericity. Hygiene, no ranking."""
        kept: list[PooledCandidate] = []
        dropped: dict[str, list[str]] = {}
        for p in pooled:
            hit = self.stoplist.hits(p.candidate)
            if hit:
                dropped.setdefault(hit, []).append(p.candidate.value)
                continue
            verdict = self.oracle.verdict(p.candidate)
            if verdict.count > self.config.lint_max_goodware_df:
                dropped.setdefault("goodware_generic", []).append(p.candidate.value)
                continue
            kept.append(p)
        return kept, dropped

    # -- arms ----------------------------------------------------------
    def run_arm(
        self,
        family: str,
        pooled: Sequence[PooledCandidate],
        arm: str,
        size_match: int | None = None,
        oracle_hits: Callable[[Candidate], bool] | None = None,
    ) -> Selection:
        if arm not in ARMS:
            raise ValueError(f"unknown arm {arm!r}; expected one of {ARMS}")

        expr, dropped = self.expressible(pooled)
        sel = Selection(family=family, arm=arm, dropped=dict(dropped),
                        peeked=arm in PEEKING_ARMS)

        if arm == "all":
            sel.selected = [p.candidate for p in expr]
            sel.stats = {"n_input": len(pooled), "n_expressible": len(expr),
                         "budgeted": False}
            return sel

        linted, lint_dropped = self.lint(expr)
        for k, v in lint_dropped.items():
            sel.dropped.setdefault(k, []).extend(v)

        if arm == "lint":
            sel.selected = [p.candidate for p in linted]
            sel.stats = {"n_input": len(pooled), "n_expressible": len(expr),
                         "n_linted": len(linted), "budgeted": False}
            return sel

        if arm == "prevalence_k":
            ranked = sorted(
                linted,
                key=lambda p: (-p.prevalence, -p.n_containing, p.candidate.key()))
        elif arm == "learned":
            scorer = self.scorer or SalienceScorer(self.oracle)
            ranked = scorer.rank(linted)
        elif arm == "analyst":
            if self.analyst is None:
                # Still refusing to fall back to another scorer: an arm that
                # silently mirrored `learned` would produce an ablation row
                # claiming an independent supervision source agreed with us.
                raise NotImplementedError(
                    "the analyst arm needs a PUBaggingScorer (ISB/mining.py). "
                    "Pass analyst= to ISB, or run the ladder without it.")
            ranked = self.analyst.rank(linted)
        elif arm == "oracle_peek":
            if oracle_hits is None:
                raise ValueError(
                    "oracle_peek needs an oracle_hits predicate -- the arm is "
                    "meaningless without the truth it peeks at")
            ranked = sorted(
                linted,
                key=lambda p: (not oracle_hits(p.candidate),
                               -p.prevalence, p.candidate.key()))
        elif arm == "random_k":
            if size_match is None:
                raise ValueError(
                    "random_k must be size-matched to the learned arm; run "
                    "learned first and pass its BUDGETED selection size")
            # Size-matching is on the BUDGETED count, and the budget-exempt
            # types (hashes) are handed to random_k too. Matching on total size
            # instead would hand random_k N ranked-type slots while learned
            # spent most of its N on free hashes -- same number, different
            # question, and not a control.
            # Mirror the budget's free/drawable split exactly, prevalence gate
            # included, so the control differs from `learned` only in ranking.
            excluded = set(self.config.budget.exclude_types)
            gate = self.config.budget.free_min_prevalence
            free = [p for p in linted if p.candidate.ctype in excluded
                    and p.prevalence >= gate]
            drawable = [p for p in linted if p.candidate.ctype not in excluded]
            rng = random.Random(f"{self.config.seed}:{family}")
            rng.shuffle(drawable)
            picked = drawable[:size_match]
            sel.selected = [p.candidate for p in free + picked]
            sel.stats = {"n_input": len(pooled), "n_expressible": len(expr),
                         "n_linted": len(linted), "size_match": size_match,
                         "n_budgeted": len(picked), "n_free": len(free),
                         "budgeted": False, "policy": "random_post_lint"}
            return sel
        else:  # pragma: no cover - guarded by the ARMS check above
            raise ValueError(arm)

        result = apply_budget(ranked, self.config.budget)
        sel.selected = [p.candidate for p in result.pop("selected")]
        sel.stats = {"n_input": len(pooled), "n_expressible": len(expr),
                     "n_linted": len(linted), "budgeted": True, **result}
        return sel

    def run_ladder(
        self,
        family: str,
        pooled: Sequence[PooledCandidate],
        arms: Sequence[str] = ARMS,
        oracle_hits: Callable[[Candidate], bool] | None = None,
    ) -> dict[str, Selection]:
        """Run several arms, honouring the learned-before-random_k ordering."""
        wanted = [a for a in arms if a != "random_k"]
        out: dict[str, Selection] = {}
        for arm in wanted:
            if arm == "oracle_peek" and oracle_hits is None:
                continue
            if arm == "analyst" and not self.analyst_available:
                continue
            out[arm] = self.run_arm(family, pooled, arm, oracle_hits=oracle_hits)
        if "random_k" in arms:
            learned = out.get("learned") or self.run_arm(family, pooled, "learned")
            out["random_k"] = self.run_arm(
                family, pooled, "random_k",
                size_match=int(learned.stats.get("n_budgeted", 0)))
        return out

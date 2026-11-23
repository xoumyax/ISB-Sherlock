"""Budget policies: how many candidates reach a rule, and which (EXP2_DESIGN §6).

A scorer ranks; a budget decides where to cut. The cut matters more than it
looks: the pre-wipe Track-A run measured **853 false positives per 1k goodware**
under a plain ``top_k`` cut, because the highest-scoring candidates cluster in
one type -- take the top 8 and you get eight variations on the same string, a
rule with one real condition and no breadth.

``type_cover`` fixes that by round-robining across candidate types before it
takes seconds from any one type, so a k=8 rule spends its budget on eight
*different kinds* of evidence. It is the only policy exposed here.

``top_k`` is deliberately **not implemented**. It is not a missing feature; it
is a known-bad policy, and leaving a working implementation lying around invites
someone to A/B it into a rule set. If it is ever needed as a *negative control*
for a paper table, add it there with the FP number in the docstring.

**Budget-exempt types are prevalence-gated** (brownie 2026-08-20). Hash terms
ride free because an exact file hash cannot cause a false positive and should
not consume a breadth slot. But at 88 gen samples per family that exemption
turned a rule into a hash blocklist -- guloader's selection was 8 ranked
candidates and **59** module terms. A sha256 carried by exactly one gen sample
cannot match anything held out, so it is pure rule weight; an imphash shared
across the family is real evidence. The gate keeps the second and drops the
first. M4 reports imphash-driven TPR as its own column so the contribution
stays visible rather than being absorbed into the headline.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .candidate import HASH_TYPES, Candidate
from .pooling import PooledCandidate

__all__ = ["BudgetConfig", "type_cover", "apply_budget"]


@dataclass(frozen=True)
class BudgetConfig:
    """The k=8 operating point carried over from Track A."""

    k: int = 8
    #: Types excluded from the budget entirely. Hashes are *free*: a file hash
    #: is exact, cannot cause a false positive, and consumes a slot that breadth
    #: needs. Making hashes free is what moved Track-A learned TPR 0.21 -> 0.29
    #: and let it decisively beat random_k.
    exclude_types: frozenset[str] = HASH_TYPES
    #: Cap per type before round-robin moves on; None = no per-type cap beyond k.
    max_per_type: int | None = None
    #: An exempt candidate rides free only if this share of the family's gen
    #: samples carries it. 0.10 drops per-sample file hashes (prevalence 1/88 on
    #: a full family) and keeps a genuinely shared imphash. Set to 0.0 to
    #: restore the old unconditional exemption.
    free_min_prevalence: float = 0.10


def _split_free(
    ranked: Sequence[PooledCandidate],
    excluded: set[str],
    min_prevalence: float,
) -> tuple[list[PooledCandidate], list[PooledCandidate], list[PooledCandidate]]:
    """-> (free, budgeted_pool, rejected_free)"""
    free, pool, rejected = [], [], []
    for p in ranked:
        if p.candidate.ctype not in excluded:
            pool.append(p)
        elif p.prevalence >= min_prevalence:
            free.append(p)
        else:
            rejected.append(p)
    return free, pool, rejected


def type_cover(
    ranked: Sequence[PooledCandidate],
    k: int = 8,
    exclude_types: Iterable[str] = HASH_TYPES,
    max_per_type: int | None = None,
    free_min_prevalence: float = 0.10,
) -> list[PooledCandidate]:
    """Take ``k`` candidates, round-robin across types, best-first within type.

    ``ranked`` must already be in descending score order -- this function does
    not sort, so the caller's ranking is visible in the output rather than
    silently re-derived.

    Exempt types that clear ``free_min_prevalence`` bypass the budget and are
    returned in full, ahead of the budgeted picks, uncounted against ``k``.
    """
    excluded = set(exclude_types)
    free, pool, _rejected = _split_free(ranked, excluded, free_min_prevalence)

    by_type: "OrderedDict[str, list[PooledCandidate]]" = OrderedDict()
    for p in pool:
        by_type.setdefault(p.candidate.ctype, []).append(p)

    picked: list[PooledCandidate] = []
    cursor: dict[str, int] = defaultdict(int)
    # Round-robin: one pass per rank position, types in first-appearance order
    # (which is score order, since `ranked` is sorted). Stops when k is met or
    # no type can contribute another candidate.
    while len(picked) < k:
        progressed = False
        for ctype, items in by_type.items():
            if len(picked) >= k:
                break
            i = cursor[ctype]
            if i >= len(items):
                continue
            if max_per_type is not None and i >= max_per_type:
                continue
            picked.append(items[i])
            cursor[ctype] = i + 1
            progressed = True
        if not progressed:
            break

    return free + picked


def apply_budget(
    ranked: Sequence[PooledCandidate],
    config: BudgetConfig | None = None,
) -> dict[str, Any]:
    """``type_cover`` plus the accounting a run report needs.

    Returns the selection *and* what it cost, because a budget that silently
    drops most of its input is indistinguishable from one that had little input
    unless the numbers are written down. ``n_free_rejected`` is called out
    separately: it is the hash-blocklist bloat the prevalence gate removes, and
    it must be legible rather than inferred from a shrinking rule.
    """
    config = config or BudgetConfig()
    excluded = set(config.exclude_types)
    selected = type_cover(
        ranked, k=config.k, exclude_types=config.exclude_types,
        max_per_type=config.max_per_type,
        free_min_prevalence=config.free_min_prevalence)
    free, _pool, rejected = _split_free(
        ranked, excluded, config.free_min_prevalence)
    budgeted = [p for p in selected if p.candidate.ctype not in excluded]
    types_available = {p.candidate.ctype for p in ranked
                       if p.candidate.ctype not in excluded}
    return {
        "selected": selected,
        "n_selected": len(selected),
        "n_budgeted": len(budgeted),
        "n_free": len(free),
        "n_free_rejected": len(rejected),
        "n_input": len(ranked),
        "k": config.k,
        "free_min_prevalence": config.free_min_prevalence,
        "types_available": len(types_available),
        "types_used": len({p.candidate.ctype for p in budgeted}),
        "policy": "type_cover",
    }

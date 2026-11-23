"""Direct-empirical supervision for the Selection Brain (EXP2_DESIGN §6).

The label a candidate gets is not an opinion: on an F_train family, a candidate
is **positive** iff it is carried by ``>= m`` of that family's gen samples *and*
by **no** G_stats goodware document. Both halves are set-membership over
material we already have -- support comes from pooling, goodware from the
oracle -- so labelling never scans a corpus and real negatives exist. That is
what lets the primary scorer be plain supervised LightGBM instead of PU
(PU-bagging survives only in the analyst-mining arm, :mod:`mining`).

**Why this is not ``pooling.positive_keys`` called verbatim.** That primitive
takes a single :class:`DFIndex` and looks every candidate up in it. Since
2026-08-20 we know a ``HEX_SPAN`` cannot be scored by the string index at all --
it would return 0 for every span, i.e. "absent from all goodware", which is
precisely the verdict that promotes a candidate. Supervision therefore routes
through :class:`~.goodware.GoodwareOracle`. The support half of the rule is
still pooling's (:meth:`FamilyCandidateSet.support`); only the goodware lookup
is routed. With a strings-only oracle the two agree exactly, and a test pins
that.

**The label must not be computable from the features.** The §6 rule as first
implemented scored support and goodware on the *same* gen samples the features
come from, which makes ``label == (prevalence >= 0.20 and goodware_rate == 0)``
-- both features. Measured 2026-08-20 on the full F_train table: agreement
**1.000000**, 3771/3771 positives, 0 false positives. The scorer hit PR-AUC 1.0
by rediscovering a two-line rule, and "learned" became a re-implementation of
``prevalence_k`` + ``lint``, the very baseline it exists to beat.

The fix is to move the support half of the rule to the family's **held** samples
(``held=`` below). Features still come from gen; the question becomes "given what
this candidate looks like on the samples I can see, will it still be there on
samples I cannot?" -- which is exactly what a rule needs to do at deployment and
is *not* derivable from gen-side prevalence. F_train held halves are legal
supervision material: evaluation never touches F_train families at all. Eval
families' held halves remain untouched by anything, ever.

**Leakage.** Labels may only be computed on F_train families. An F_dev or
F_test family has no business producing training labels, and the guard raises
rather than warns -- a defaulted-off leakage protection is an accidental
off-switch.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .candidate import HEX_TYPES
from .goodware import GoodwareOracle
from .pooling import FamilyCandidateSet, PooledCandidate

__all__ = [
    "SupervisionConfig",
    "FamilyLabels",
    "label_family",
    "build_training_table",
]


@dataclass(frozen=True)
class SupervisionConfig:
    """The label rule's parameters (§6 defaults; ``m`` is F_dev-tuned)."""

    #: ``m = max(m_floor, ceil(m_frac * n_gen))`` -- pooling's default_m.
    m_floor: int = 2
    m_frac: float = 0.20
    #: Goodware documents tolerated before a candidate stops being positive.
    #: 0 is the design rule; the knob exists so §6's strictness can be *studied*,
    #: not so it can be quietly loosened.
    max_goodware_df: int = 0
    #: Refuse to label hex spans when no span index is loaded. Without one every
    #: span scores goodware_df == 0 and every span becomes positive -- the exact
    #: failure the 2026-08-20 attribution smoke found.
    require_span_index: bool = True
    #: Candidates below this family support are not labelled at all (neither
    #: positive nor negative). A value seen once is evidence of nothing.
    min_support_for_negative: int = 1
    #: Negatives kept per positive, per family, seeded. At ~0.05% positive a
    #: full table is ~1.3M rows per family (~30M across F_train) and will not
    #: fit in memory; nothing is learned from the 1,299,999th near-duplicate
    #: negative that is not in the first 25,000. 0 disables the cap.
    negative_cap_ratio: int = 50
    #: Families exempt from the cap. The driver passes its holdout families so
    #: the PR-AUC denominator is the real negative population -- a subsampled
    #: holdout would report an optimistic precision and quietly flatter us.
    full_negative_families: frozenset[str] = frozenset()
    seed: int = 20260809


@dataclass
class FamilyLabels:
    """Labels for one family, plus why each candidate landed where it did."""

    family: str
    m: int
    n_samples: int
    positives: set[tuple[str, str, str]] = field(default_factory=set)
    negatives: set[tuple[str, str, str]] = field(default_factory=set)
    #: key -> the first rule that denied it a positive label (auditability).
    denied: dict[tuple[str, str, str], str] = field(default_factory=dict)
    by_ctype: dict[str, Counter] = field(default_factory=dict)
    #: "held" once the tautology fix is active; "gen" is the old, degenerate form.
    support_side: str = "gen"

    @property
    def n_positive(self) -> int:
        return len(self.positives)

    @property
    def n_negative(self) -> int:
        return len(self.negatives)

    @property
    def positive_rate(self) -> float:
        total = self.n_positive + self.n_negative
        return self.n_positive / total if total else 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "family": self.family, "m": self.m, "n_samples": self.n_samples,
            "n_positive": self.n_positive, "n_negative": self.n_negative,
            "positive_rate": round(self.positive_rate, 4),
            "support_side": self.support_side,
            "denied_reasons": dict(Counter(self.denied.values())),
            "by_ctype": {k: dict(v) for k, v in self.by_ctype.items()},
        }


def label_family(
    fcs: FamilyCandidateSet,
    oracle: GoodwareOracle,
    config: SupervisionConfig | None = None,
    m: int | None = None,
    held: FamilyCandidateSet | None = None,
) -> FamilyLabels:
    """Label every candidate of one F_train family.

    Candidates are enumerated from ``fcs`` (the gen side, which is where the
    features come from). When ``held`` is supplied the **support** half of the
    rule is evaluated against it instead -- see the module docstring for why
    scoring support on the feature-bearing samples makes the label tautological.
    A gen candidate absent from every held sample gets support 0 and is a
    negative, which is the informative case.

    ``denied`` records the first failing rule per candidate, so a scorer trained
    on a bad label distribution can be diagnosed from the artifact instead of by
    re-deriving the run.
    """
    config = config or SupervisionConfig()
    support_set = held if held is not None else fcs
    n = support_set.n_samples
    m = m if m is not None else FamilyCandidateSet.default_m(
        n, floor=config.m_floor, frac=config.m_frac)

    scored = oracle.scored_types
    out = FamilyLabels(family=fcs.family, m=m, n_samples=n)
    out.support_side = "held" if held is not None else "gen"

    for key in fcs.keys():
        cand = fcs.candidate_for(key)
        ctype = cand.ctype
        bucket = out.by_ctype.setdefault(ctype, Counter())
        support = support_set.support(key)

        if ctype in HEX_TYPES and config.require_span_index and not scored["spans"]:
            out.denied[key] = "no_span_index"
            bucket["denied_no_span_index"] += 1
            continue
        if support < m:
            out.negatives.add(key)
            out.denied[key] = "support_below_m"
            bucket["negative_support"] += 1
            continue

        verdict = oracle.verdict(cand)
        if verdict.index == "none":
            out.denied[key] = "unscored_goodware"
            bucket["denied_unscored"] += 1
            continue
        if verdict.count > config.max_goodware_df:
            out.negatives.add(key)
            out.denied[key] = "goodware_present"
            bucket["negative_goodware"] += 1
            continue

        out.positives.add(key)
        bucket["positive"] += 1

    return out


def build_training_table(
    family_sets: Sequence[FamilyCandidateSet],
    pooled: Mapping[str, Sequence[PooledCandidate]],
    oracle: GoodwareOracle,
    config: SupervisionConfig | None = None,
    allowed_families: Iterable[str] | None = None,
    allow_all: bool = False,
    held_sets: Mapping[str, FamilyCandidateSet] | None = None,
) -> dict[str, Any]:
    """Assemble the supervised training table across F_train families.

    ``pooled`` supplies the feature rows (pooling owns featurization so Exp 1,
    Exp 2 and the labeller cannot drift apart); this function supplies the
    labels and the join. Rows whose candidate was denied a label are dropped,
    not defaulted to negative -- "we could not score this" and "goodware has
    this" are different facts and must not be trained as the same one.

    ``allowed_families`` is the F_train leakage guard. It is required for the
    same reason ``pool_families``' is: an omitted guard must not silently pass.
    """
    config = config or SupervisionConfig()
    if allowed_families is None and not allow_all:
        raise ValueError(
            "allowed_families is required (pass the F_train family list) or "
            "set allow_all=True to explicitly skip the leakage guard")
    allowed = None if allow_all else set(allowed_families or ())

    if allowed is not None:
        bad = [fcs.family for fcs in family_sets if fcs.family not in allowed]
        if bad:
            raise AssertionError(
                f"LEAKAGE: supervision asked to label non-F_train families {bad}. "
                "Labels may only come from F_train (EXP2_DESIGN §6).")

    rows: list[dict[str, Any]] = []
    labels: list[int] = []
    groups: list[str] = []
    per_family: dict[str, dict[str, Any]] = {}

    for fcs in family_sets:
        fam_labels = label_family(
            fcs, oracle, config, held=(held_sets or {}).get(fcs.family))
        per_family[fcs.family] = fam_labels.summary()
        by_key = {p.candidate.key(): p for p in pooled.get(fcs.family, ())}

        positives = sorted(fam_labels.positives)
        negatives = sorted(fam_labels.negatives)
        kept_frac = 1.0
        if (config.negative_cap_ratio
                and fcs.family not in config.full_negative_families):
            cap = max(config.negative_cap_ratio * len(positives),
                      config.negative_cap_ratio)
            if len(negatives) > cap:
                rng = random.Random(f"{config.seed}:{fcs.family}")
                kept_frac = cap / len(negatives)
                negatives = sorted(rng.sample(negatives, cap))
        per_family[fcs.family]["negatives_kept_frac"] = round(kept_frac, 6)
        per_family[fcs.family]["n_negatives_available"] = len(fam_labels.negatives)

        for key in positives + negatives:
            pc = by_key.get(key)
            if pc is None:
                continue
            feats = dict(pc.features())
            # The pooled row's goodware stats came from whichever index pooling
            # was handed. Re-state the RATE from the oracle so hex spans carry a
            # real number instead of a structural zero. The raw count is not a
            # feature (see PooledCandidate.features).
            verdict = oracle.verdict(pc.candidate)
            feats["goodware_rate"] = verdict.rate
            rows.append(feats)
            labels.append(1 if key in fam_labels.positives else 0)
            groups.append(fcs.family)

    n_pos = sum(labels)
    return {
        "rows": rows,
        "labels": labels,
        "groups": groups,
        "feature_names": sorted(rows[0]) if rows else [],
        "per_family": per_family,
        "summary": {
            "n_rows": len(rows),
            "n_positive": n_pos,
            "n_negative": len(labels) - n_pos,
            "positive_rate": round(n_pos / len(labels), 4) if labels else 0.0,
            "n_families": len(family_sets),
            "goodware_scored": oracle.scored_types,
            "support_side": "held" if held_sets else "gen",
            "negative_cap_ratio": config.negative_cap_ratio,
            "full_negative_families": sorted(config.full_negative_families),
            "config": {
                "m_floor": config.m_floor, "m_frac": config.m_frac,
                "max_goodware_df": config.max_goodware_df,
                "require_span_index": config.require_span_index,
            },
        },
    }

"""Family-level candidate pooling and support statistics.

The front end emits candidates *per sample*; selection reasons *per family*. This
module is the join: it pools per-sample candidate sets into unique candidates
carrying the support statistics that ISB-A's scorer consumes
(EXP2_DESIGN §5, §6).

Everything here is set membership over the per-sample candidate sets -- no
scanning. That matters twice over: it is orders of magnitude cheaper than
running YARA, and it is the *same* primitive that produces ISB-A's supervision
labels ("present in >=m other gen samples AND 0 goodware"), so the label
definition and the feature definition cannot drift apart.

Leakage is enforced in code, not convention: cross-family promiscuity may only
be counted over an explicitly allowed family set (F_train), and the constructor
refuses anything else.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .candidate import Candidate

__all__ = [
    "CandKey",
    "DFIndex",
    "PooledCandidate",
    "FamilyCandidateSet",
    "build_xfam_index",
    "value_entropy",
]

CandKey = tuple[str, str, str]


def value_entropy(value: str) -> float:
    """Shannon entropy over the value's characters (a scorer feature)."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class DFIndex:
    """Goodware document-frequency index over G_stats only.

    ``n_docs`` is needed to turn a raw count into a rate; keeping both means
    downstream code never has to guess the corpus size behind a DF value.

    Lookups case-fold by default, matching how the index is built
    (``StaticFeatures/dfindex.py``): genericity is a property of the value, and
    case-folding can only make a candidate look *more* generic, never less, so it
    cannot hide FP risk. Case-sensitive candidate types keep their case in
    ``norm`` for rendering, so the fold has to happen here.
    """

    df: Mapping[str, int] = field(default_factory=dict)
    n_docs: int = 0
    source: str | None = None
    casefold: bool = True

    def count(self, norm_value: str) -> int:
        probe = norm_value.lower() if self.casefold else norm_value
        return int(self.df.get(probe, 0))

    def rate(self, norm_value: str) -> float:
        return self.count(norm_value) / self.n_docs if self.n_docs else 0.0

    def __contains__(self, norm_value: str) -> bool:
        return self.count(norm_value) > 0


@dataclass
class PooledCandidate:
    """A unique candidate plus its family-level support statistics."""

    candidate: Candidate
    n_containing: int
    n_samples: int
    goodware_df: int = 0
    goodware_n_docs: int = 0
    xfam_promiscuity: int = 0
    xfam_n_families: int = 0
    attribution_bin: float = 0.0
    attribution_fam: float = 0.0
    sources: tuple[str, ...] = ()
    containing_shas: tuple[str, ...] = ()

    @property
    def prevalence(self) -> float:
        """Fraction of the family's gen samples containing this candidate."""
        return self.n_containing / self.n_samples if self.n_samples else 0.0

    @property
    def goodware_rate(self) -> float:
        return self.goodware_df / self.goodware_n_docs if self.goodware_n_docs else 0.0

    @property
    def xfam_rate(self) -> float:
        return (
            self.xfam_promiscuity / self.xfam_n_families
            if self.xfam_n_families else 0.0
        )

    def features(self) -> dict[str, float]:
        """The shared scorer feature core (EXP2_DESIGN §6).

        Defined here rather than in ``salience.py`` so Exp 1 and Exp 2, and the
        supervision labeller, all featurize identically.

        **Rates only, never raw support counts** (brownie 2026-08-20). The raw
        forms stay in :meth:`to_dict` for reporting, but they must not reach the
        scorer:

        * ``n_containing`` = ``prevalence * n_samples``, and ``n_samples``
          varies per family. On the 4-family fit it out-ranked ``prevalence``
          2292 to 199 -- the model was keying on how big a family is, which is
          a property of our corpus, not of the candidate. Eval families have
          different gen counts, so that is a straight distribution shift.
        * ``goodware_df`` is not comparable across candidate types at all: the
          string index holds 3,595 documents (per-source cap) and the span index
          10,620, so the same count means different genericity depending on
          which index answered. ``goodware_rate`` normalises that away.
        """
        c = self.candidate
        value = c.value
        alpha = sum(1 for ch in value if ch.isalpha())
        return {
            "length": float(len(value)),
            "printable_len": float(c.printable_len),
            "entropy": value_entropy(value),
            "frac_alpha": alpha / len(value) if value else 0.0,
            "frac_digit": (
                sum(1 for ch in value if ch.isdigit()) / len(value) if value else 0.0
            ),
            "has_space": 1.0 if " " in value else 0.0,
            "prevalence": self.prevalence,
            "goodware_rate": self.goodware_rate,
            # xfam_promiscuity is kept: its denominator is the F_train family
            # count, which is constant within a run, so it is a fixed rescaling
            # of xfam_rate and carries no family-size confound.
            "xfam_promiscuity": float(self.xfam_promiscuity),
            "xfam_rate": self.xfam_rate,
            "attribution_bin": self.attribution_bin,
            "attribution_fam": self.attribution_fam,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.candidate.to_dict()
        d.update({
            "n_containing": self.n_containing,
            "n_samples": self.n_samples,
            "prevalence": self.prevalence,
            "goodware_df": self.goodware_df,
            "xfam_promiscuity": self.xfam_promiscuity,
            "attribution_bin": self.attribution_bin,
            "attribution_fam": self.attribution_fam,
            "sources": list(self.sources),
        })
        return d


def build_xfam_index(
    family_candidate_keys: Mapping[str, Iterable[CandKey]],
    allowed_families: Iterable[str] | None = None,
) -> tuple[dict[CandKey, int], int]:
    """Count, per candidate key, how many families contain it.

    ``allowed_families`` is the leakage guard: promiscuity must be computed over
    F_train families only (EXP2_DESIGN §5), because counting an F_test family
    would leak evaluation information into a training-time feature. Passing a
    family outside the allowed set raises.
    """
    allowed = set(allowed_families) if allowed_families is not None else None
    if allowed is not None:
        illegal = sorted(set(family_candidate_keys) - allowed)
        if illegal:
            raise ValueError(
                f"xfam index would leak: families outside allowed set: {illegal}"
            )
    index: dict[CandKey, int] = defaultdict(int)
    families = list(family_candidate_keys)
    for fam in families:
        for key in set(family_candidate_keys[fam]):
            index[key] += 1
    return dict(index), len(families)


class FamilyCandidateSet:
    """Per-sample candidate sets for ONE family, poolable into statistics.

    Usage::

        fcs = FamilyCandidateSet("agenttesla")
        for sha, cands in per_sample.items():
            fcs.add_sample(sha, cands)
        pooled = fcs.pool(df_index=df, xfam_index=xfam, xfam_n_families=23)
    """

    def __init__(self, family: str):
        self.family = family
        self._samples: dict[str, set[CandKey]] = {}
        self._by_key: dict[CandKey, Candidate] = {}
        self._sources: dict[CandKey, set[str]] = defaultdict(set)
        self._attr_bin: dict[CandKey, float] = {}
        self._attr_fam: dict[CandKey, float] = {}

    # -- construction --------------------------------------------------
    def add_sample(self, sha256: str, candidates: Iterable[Candidate]) -> None:
        """Register one sample's candidates.

        Re-adding the same sha replaces its set, so a resumed extraction pass
        cannot double-count a sample into prevalence.
        """
        keys: set[CandKey] = set()
        for cand in candidates:
            key = cand.key()
            keys.add(key)
            self._by_key.setdefault(key, cand)
            if cand.source:
                self._sources[key].add(cand.source)
            # Attribution scores are per-candidate evidence; take the max across
            # samples -- the strongest evidence anywhere in the family.
            ab = float(cand.attrs.get("attribution_bin", 0.0) or 0.0)
            af = float(cand.attrs.get("attribution_fam", 0.0) or 0.0)
            if ab > self._attr_bin.get(key, 0.0):
                self._attr_bin[key] = ab
            if af > self._attr_fam.get(key, 0.0):
                self._attr_fam[key] = af
        self._samples[sha256] = keys

    # -- queries -------------------------------------------------------
    @property
    def n_samples(self) -> int:
        return len(self._samples)

    @property
    def shas(self) -> tuple[str, ...]:
        return tuple(self._samples)

    def keys(self) -> set[CandKey]:
        out: set[CandKey] = set()
        for keys in self._samples.values():
            out |= keys
        return out

    def containing(self, key: CandKey) -> tuple[str, ...]:
        return tuple(sha for sha, keys in self._samples.items() if key in keys)

    def candidate_for(self, key: CandKey) -> Candidate:
        """The Candidate behind a key. Read-only accessor over the key index.

        Supervision needs the candidate's ``ctype`` to route its goodware lookup
        (strings vs byte spans), and only the key set is public otherwise.
        """
        return self._by_key[key]

    def support(self, key: CandKey) -> int:
        """Number of samples in this family containing ``key``."""
        return sum(1 for keys in self._samples.values() if key in keys)

    def support_excluding(self, key: CandKey, sha256: str) -> int:
        """Support counted over every sample *except* ``sha256``.

        This is the primitive ISB-A supervision needs: a candidate is positive
        for a given sample iff it also appears in >=m *other* samples of the
        family. Counting the sample itself would make every candidate trivially
        supported at m=1.
        """
        return sum(
            1 for sha, keys in self._samples.items() if sha != sha256 and key in keys
        )

    # -- pooling -------------------------------------------------------
    def pool(
        self,
        df_index: DFIndex | None = None,
        xfam_index: Mapping[CandKey, int] | None = None,
        xfam_n_families: int = 0,
        min_support: int = 1,
        keep_shas: bool = False,
    ) -> list[PooledCandidate]:
        """Pool into unique candidates with support statistics.

        ``min_support`` drops candidates seen in fewer than N samples before any
        expensive downstream work; the default keeps everything so the ``all``
        arm remains a faithful no-selection reference.
        """
        df_index = df_index or DFIndex()
        xfam_index = xfam_index or {}
        n = self.n_samples

        support_counts: Counter[CandKey] = Counter()
        for keys in self._samples.values():
            support_counts.update(keys)

        out: list[PooledCandidate] = []
        for key, count in support_counts.items():
            if count < min_support:
                continue
            cand = self._by_key[key]
            out.append(PooledCandidate(
                candidate=cand,
                n_containing=count,
                n_samples=n,
                goodware_df=df_index.count(cand.norm),
                goodware_n_docs=df_index.n_docs,
                xfam_promiscuity=int(xfam_index.get(key, 0)),
                xfam_n_families=xfam_n_families,
                attribution_bin=self._attr_bin.get(key, 0.0),
                attribution_fam=self._attr_fam.get(key, 0.0),
                sources=tuple(sorted(self._sources.get(key, ()))),
                containing_shas=self.containing(key) if keep_shas else (),
            ))
        # Deterministic order: prevalence desc, then key -- pooling output feeds
        # size-matched random_k draws, so a stable order keeps runs reproducible.
        out.sort(key=lambda p: (-p.n_containing, p.candidate.key()))
        return out

    # -- supervision primitive ----------------------------------------
    def positive_keys(
        self,
        m: int,
        df_index: DFIndex | None = None,
        max_goodware_df: int = 0,
    ) -> set[CandKey]:
        """Keys satisfying the direct-empirical positive rule (EXP2_DESIGN §6).

        **Convention: ``m`` is a TOTAL support count.** A candidate is positive
        iff it appears in ``>= m`` samples of the family (the sample itself
        included) AND in at most ``max_goodware_df`` G_stats goodware documents
        (0 = absent).

        This is the single authoritative reading of ``m`` for supervision. The
        design docs phrase it two ways -- "≥m *other* gen samples" (§6) versus
        "≥m of the family's gen samples" (§4) -- which differ by one; total-count
        is the convention adopted here, and §6 is amended to match. ``m`` is
        F_dev-tuned, so the choice has no numeric consequence, but the label
        definition has to be unambiguous before the scorer trains on it.

        Use :meth:`support_excluding` when you need the strict "other samples"
        count for a specific sample.
        """
        df_index = df_index or DFIndex()
        out: set[CandKey] = set()
        for key, count in Counter(
            k for keys in self._samples.values() for k in keys
        ).items():
            if count < m:
                continue
            if df_index.count(self._by_key[key].norm) > max_goodware_df:
                continue
            out.add(key)
        return out

    @staticmethod
    def default_m(n_gen: int, floor: int = 2, frac: float = 0.20) -> int:
        """``m = max(2, 20% of gen)`` -- the EXP2_DESIGN §4 default."""
        return max(floor, int(math.ceil(frac * n_gen)))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"FamilyCandidateSet({self.family!r}, n_samples={self.n_samples}, "
            f"n_unique={len(self.keys())})"
        )


def pool_families(
    family_sets: Sequence[FamilyCandidateSet],
    allowed_xfam_families: Iterable[str] | None = None,
    df_index: DFIndex | None = None,
    allow_all: bool = False,
    **pool_kwargs: Any,
) -> dict[str, list[PooledCandidate]]:
    """Pool several families, computing cross-family promiscuity across them.

    ``allowed_xfam_families`` is the leakage guard forwarded to
    :func:`build_xfam_index` -- pass the F_train family list. It is **required**:
    a defaulted-to-None guard is an accidental off-switch, so callers must state
    intent, and ``allow_all=True`` is the explicit escape hatch (tests, ad-hoc
    inspection) rather than an omission that silently passes.
    """
    if allowed_xfam_families is None and not allow_all:
        raise ValueError(
            "allowed_xfam_families is required (pass the F_train family list) "
            "or set allow_all=True to explicitly skip the leakage guard"
        )
    xfam_index, n_fams = build_xfam_index(
        {fcs.family: fcs.keys() for fcs in family_sets},
        allowed_families=None if allow_all else allowed_xfam_families,
    )
    return {
        fcs.family: fcs.pool(
            df_index=df_index,
            xfam_index=xfam_index,
            xfam_n_families=n_fams,
            **pool_kwargs,
        )
        for fcs in family_sets
    }

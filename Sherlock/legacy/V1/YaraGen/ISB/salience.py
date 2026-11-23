"""ISB-A, the Selection Brain: score candidates for inclusion (EXP2_DESIGN §6).

Plain supervised LightGBM. The labels from :mod:`supervision` are direct and
family-disjoint, so real negatives exist and there is nothing for PU learning to
do -- PU-bagging survives only in the analyst-mining arm.

**The scorer is given everything, prevalence included.** That is deliberate and
it raises the bar on ourselves: ``prevalence_k`` (the yarGen-shaped heuristic,
roughly "most prevalent candidates absent from goodware") is the baseline the
learned arm must beat, and letting the learned arm see prevalence means a win is
a win about *weighting*, not about having been handed a feature the baseline
lacked.

Two guards worth knowing about:

* **Featurization is pooling's**, not this module's. If the scorer featurized
  independently, training and inference could drift apart silently and nothing
  would fail loudly. :meth:`SalienceScorer.featurize` only re-states the
  goodware columns through the oracle, for the reason given in
  :mod:`supervision`.
* **Validation is F_dev, never F_test.** F_test runs once, at the end.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .goodware import GoodwareOracle
from .pooling import PooledCandidate

__all__ = ["SalienceConfig", "PriorScorer", "SalienceScorer"]


@dataclass(frozen=True)
class SalienceConfig:
    """LightGBM hyper-parameters and the fallback threshold."""

    n_estimators: int = 300
    learning_rate: float = 0.05
    num_leaves: int = 31
    min_child_samples: int = 20
    subsample: float = 0.9
    colsample_bytree: float = 0.9
    seed: int = 20260809
    #: Below this many positives, LightGBM is not trained at all and the prior
    #: scorer is used. A tree ensemble fitted on a handful of positives is a
    #: memorised list, not a model, and it would look fine in-sample.
    min_positives: int = 30
    #: Class weighting for the (heavily negative) label distribution.
    class_weight: str | None = "balanced"
    #: Fraction of FAMILIES held out to score the scorer. Grouped by family on
    #: purpose: a random row holdout would put candidates from the same family
    #: on both sides and report memorisation as generalisation, and deployment
    #: is always an unseen family.
    holdout_family_frac: float = 0.25
    #: Minimum families before a grouped holdout is attempted at all.
    min_families_for_holdout: int = 4


class PriorScorer:
    """Deterministic fallback: the heuristic the learned arm has to beat.

    Score = prevalence, penalised by goodware genericity and cross-family
    promiscuity. This is deliberately close to ``prevalence_k`` / yarGen logic,
    so when it is used as a *fallback* the run degrades to a known baseline
    rather than to noise.
    """

    name = "prior"

    def __init__(self, oracle: GoodwareOracle | None = None):
        self.oracle = oracle or GoodwareOracle()

    def score_one(self, pc: PooledCandidate) -> float:
        verdict = self.oracle.verdict(pc.candidate)
        goodware_penalty = 1.0 / (1.0 + verdict.count)
        xfam_penalty = 1.0 / (1.0 + pc.xfam_promiscuity)
        return float(pc.prevalence * goodware_penalty * xfam_penalty)

    def score(self, pooled: Sequence[PooledCandidate]) -> list[float]:
        return [self.score_one(p) for p in pooled]


class SalienceScorer:
    """Supervised LightGBM over the shared feature core."""

    name = "learned"

    def __init__(
        self,
        oracle: GoodwareOracle | None = None,
        config: SalienceConfig | None = None,
    ):
        self.oracle = oracle or GoodwareOracle()
        self.config = config or SalienceConfig()
        self.model = None
        self.feature_names: list[str] = []
        self.fallback: PriorScorer | None = None
        self.train_summary: dict[str, Any] = {}

    # -- features ------------------------------------------------------
    def featurize(self, pc: PooledCandidate) -> dict[str, float]:
        """Pooling's feature core, with goodware re-stated through the oracle."""
        feats = dict(pc.features())
        feats["goodware_rate"] = self.oracle.verdict(pc.candidate).rate
        return feats

    def _matrix(self, rows: Sequence[Mapping[str, float]]):
        """Dense matrix in ``feature_names`` order.

        numpy rather than a list of lists so fit and predict present the same
        type; a bare list makes LightGBM synthesise column names at fit time and
        then warn at predict that they are missing.
        """
        import numpy as np
        return np.asarray(
            [[float(r.get(k, 0.0)) for k in self.feature_names] for r in rows],
            dtype=float).reshape(len(rows), len(self.feature_names))

    # -- training ------------------------------------------------------
    @staticmethod
    def pr_auc(labels: Sequence[int], scores: Sequence[float]) -> float:
        """Average precision.

        PR-AUC, not ROC-AUC (brownie 2026-08-20): the label distribution is
        ~0.05% positive, where ROC-AUC is dominated by the trivial negatives and
        reads high for a scorer that is useless at the only operating point that
        matters -- the top of the ranking, which is all the budget ever sees.
        """
        from sklearn.metrics import average_precision_score
        if not labels or len(set(labels)) < 2:
            return float("nan")
        return float(average_precision_score(list(labels), list(scores)))

    @staticmethod
    def pick_holdout(families: Sequence[str], frac: float = 0.25,
                     seed: int = 20260809) -> list[str]:
        """Deterministic family holdout, exposed so the driver can choose it
        before building the table (see SupervisionConfig.full_negative_families)."""
        import random as _random
        fams = sorted(set(families))
        if len(fams) < 4:
            return []
        rng = _random.Random(seed)
        shuffled = list(fams)
        rng.shuffle(shuffled)
        return sorted(shuffled[:max(1, int(round(frac * len(fams))))])

    def _grouped_holdout(
        self, groups: Sequence[str]
    ) -> tuple[list[int], list[int], list[str]]:
        """Split row indices by family. Returns (train_idx, val_idx, val_fams)."""
        import random as _random
        fams = sorted(set(groups))
        cfg = self.config
        if len(fams) < cfg.min_families_for_holdout:
            return list(range(len(groups))), [], []
        rng = _random.Random(cfg.seed)
        shuffled = list(fams)
        rng.shuffle(shuffled)
        n_val = max(1, int(round(cfg.holdout_family_frac * len(fams))))
        val_fams = set(shuffled[:n_val])
        train_idx = [i for i, g in enumerate(groups) if g not in val_fams]
        val_idx = [i for i, g in enumerate(groups) if g in val_fams]
        return train_idx, val_idx, sorted(val_fams)

    def fit(
        self,
        rows: Sequence[Mapping[str, float]],
        labels: Sequence[int],
        feature_names: Sequence[str] | None = None,
        groups: Sequence[str] | None = None,
        holdout_families: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Fit on the supervision table. Falls back to the prior scorer when
        the positive count cannot support a tree ensemble.

        When ``groups`` (per-row family) is supplied, a family-grouped holdout is
        carved out first and the fitted model is scored on it with PR-AUC, next
        to the ``prevalence`` baseline on the same rows -- the learned arm has to
        clear the heuristic, so the comparison belongs in the training artifact
        rather than in someone's head.
        """
        self.feature_names = list(
            feature_names or (sorted(rows[0]) if rows else []))
        n_pos = int(sum(labels))
        n_neg = len(labels) - n_pos

        if n_pos < self.config.min_positives or n_neg == 0:
            self.fallback = PriorScorer(self.oracle)
            self.model = None
            self.train_summary = {
                "fitted": False, "reason": "insufficient_positives",
                "n_positive": n_pos, "n_negative": n_neg,
                "min_positives": self.config.min_positives,
                "scorer": self.fallback.name,
            }
            return self.train_summary

        import lightgbm as lgb

        cfg = self.config
        self.model = lgb.LGBMClassifier(
            n_estimators=cfg.n_estimators,
            learning_rate=cfg.learning_rate,
            num_leaves=cfg.num_leaves,
            min_child_samples=cfg.min_child_samples,
            subsample=cfg.subsample,
            colsample_bytree=cfg.colsample_bytree,
            random_state=cfg.seed,
            class_weight=cfg.class_weight,
            verbose=-1,
        )
        if groups and holdout_families is not None:
            # Explicit holdout: the driver picks it so the same families can be
            # exempted from negative subsampling upstream.
            held = set(holdout_families)
            train_idx = [i for i, g in enumerate(groups) if g not in held]
            val_idx = [i for i, g in enumerate(groups) if g in held]
            val_fams = sorted(held & set(groups))
        elif groups:
            train_idx, val_idx, val_fams = self._grouped_holdout(groups)
        else:
            train_idx, val_idx, val_fams = list(range(len(rows))), [], []
        fit_rows = [rows[i] for i in train_idx]
        fit_labels = [labels[i] for i in train_idx]

        self.model.fit(self._matrix(fit_rows), list(fit_labels))
        self.fallback = None

        evaluation: dict[str, Any] = {"held_out_families": val_fams}
        if val_idx and len(set(labels[i] for i in val_idx)) == 2:
            val_rows = [rows[i] for i in val_idx]
            val_labels = [labels[i] for i in val_idx]
            proba = self.model.predict_proba(self._matrix(val_rows))
            evaluation.update({
                "pr_auc": round(self.pr_auc(val_labels, [p[1] for p in proba]), 5),
                # Same rows, the heuristic the learned arm must beat.
                "pr_auc_prevalence_baseline": round(self.pr_auc(
                    val_labels, [float(r.get("prevalence", 0.0)) for r in val_rows]), 5),
                "n_val_rows": len(val_idx),
                "n_val_positive": int(sum(val_labels)),
            })
        else:
            evaluation["skipped"] = (
                "no held-out family carried both labels" if val_idx
                else "too few families for a grouped holdout")

        self.train_summary = {
            "fitted": True, "n_rows": len(fit_rows), "n_rows_total": len(rows),
            "n_positive": n_pos, "n_negative": n_neg,
            "positive_rate": round(n_pos / len(labels), 4) if labels else 0.0,
            "feature_names": self.feature_names,
            "scorer": self.name,
            "evaluation": evaluation,
        }
        return self.train_summary

    # -- inference -----------------------------------------------------
    def score(self, pooled: Sequence[PooledCandidate]) -> list[float]:
        if not pooled:
            return []
        if self.model is None:
            return (self.fallback or PriorScorer(self.oracle)).score(pooled)
        rows = [self.featurize(p) for p in pooled]
        proba = self.model.predict_proba(self._matrix(rows))
        return [float(p[1]) for p in proba]

    def rank(self, pooled: Sequence[PooledCandidate]) -> list[PooledCandidate]:
        """Descending score. Ties break on the candidate key so a run is
        reproducible -- ``random_k`` is size-matched against this ordering."""
        scored = list(zip(self.score(pooled), pooled))
        scored.sort(key=lambda sp: (-sp[0], sp[1].candidate.key()))
        return [p for _s, p in scored]

    def feature_importances(self) -> dict[str, float]:
        """Named importances. The DoD asks these to be dumped and eyeballed:
        prevalence and the attribution scores mattering is the sanity check."""
        if self.model is None:
            return {}
        imps = getattr(self.model, "feature_importances_", [])
        return {n: float(v) for n, v in zip(self.feature_names, imps)}

    # -- persistence ---------------------------------------------------
    def save(self, out_dir: str, stem: str = "salience") -> dict[str, str]:
        os.makedirs(out_dir, exist_ok=True)
        meta_path = os.path.join(out_dir, f"{stem}.meta.json")
        with open(meta_path, "w") as fh:
            json.dump({
                "config": asdict(self.config),
                "feature_names": self.feature_names,
                "train_summary": self.train_summary,
                "feature_importances": self.feature_importances(),
            }, fh, indent=2)
        paths = {"meta": meta_path}
        if self.model is not None:
            model_path = os.path.join(out_dir, f"{stem}.txt")
            self.model.booster_.save_model(model_path)
            paths["model"] = model_path
        return paths

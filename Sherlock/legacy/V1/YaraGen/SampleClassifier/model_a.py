"""Classifier (A): string-presence LightGBM over the M1 extraction cache.

Two jobs (EXP2_DESIGN §4):

1. **Ranked string candidates.** Gain/SHAP attribution over presence features
   points directly at *strings* -- no decoding step, unlike the byte model.
2. **The sanity baseline for classifier (B).** If the byte CNN cannot beat string
   presence, then "byte-level discovery" bought nothing, and the honest reading is
   that the signal was in the strings all along. Running the cheap model first
   means that question gets answered rather than assumed.

Features are binary presence over a vocabulary built from the **training split
only** -- building the vocabulary over all samples would leak F_dev/F_test
vocabulary into a training-time artifact even if the labels never moved.
"""

from __future__ import annotations

import json
import os
import pickle
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

import numpy as np

from .data import FAMILY_UNLABELED, SampleRef

__all__ = ["ModelAConfig", "StringPresenceClassifier", "record_feature_values"]


@dataclass(frozen=True)
class ModelAConfig:
    #: A value must appear in at least this many training samples to be a feature.
    min_df: int = 2
    #: Vocabulary cap, taken by descending training-document frequency.
    max_features: int = 2_000_000
    n_estimators: int = 400
    learning_rate: float = 0.05
    num_leaves: int = 63
    min_child_samples: int = 10
    subsample: float = 0.9
    colsample_bytree: float = 0.3
    seed: int = 20260809
    n_jobs: int = 32
    #: Cap on strings taken per record (packed samples hit the 20k extraction cap
    #: and would otherwise dominate the vocabulary).
    max_values_per_record: int = 20_000


def record_feature_values(rec: Mapping[str, Any]) -> set[str]:
    """Case-folded presence features from one extraction record.

    Deliberately the same field coverage as the goodware DF index
    (``StaticFeatures/dfindex.record_values``): the two are answering the same
    question about the same value space, and letting them drift would mean a
    candidate's DF statistic and its classifier attribution referred to different
    things.
    """
    from ..StaticFeatures.dfindex import record_values
    return record_values(rec)


class StringPresenceClassifier:
    """Sparse binary-presence LightGBM with a binary head and a family head."""

    def __init__(self, config: ModelAConfig | None = None):
        self.config = config or ModelAConfig()
        self.vocab: dict[str, int] = {}
        self.family_names: list[str] = []
        self.model_binary = None
        self.model_family = None

    # -- featurization -------------------------------------------------
    def _values_of(
        self,
        refs: Sequence[SampleRef],
        get_record: Callable[[str], Mapping[str, Any] | None],
    ) -> list[set[str]]:
        """Presence-value sets per ref, in order."""
        out: list[set[str]] = []
        for ref in refs:
            rec = get_record(ref.sha256)
            values = record_feature_values(rec) if rec else set()
            if len(values) > self.config.max_values_per_record:
                values = set(sorted(values)[: self.config.max_values_per_record])
            out.append(values)
        return out

    def build_vocab(
        self,
        refs: Sequence[SampleRef],
        get_record: Callable[[str], Mapping[str, Any] | None],
        value_sets: Sequence[set[str]] | None = None,
    ) -> dict[str, int]:
        """Vocabulary from TRAINING refs only, by descending document frequency."""
        from collections import Counter

        if value_sets is None:
            value_sets = self._values_of(refs, get_record)
        df: Counter[str] = Counter()
        for values in value_sets:
            df.update(values)

        kept = [(v, c) for v, c in df.items() if c >= self.config.min_df]
        kept.sort(key=lambda vc: (-vc[1], vc[0]))     # deterministic tie-break
        kept = kept[: self.config.max_features]
        self.vocab = {v: i for i, (v, _c) in enumerate(kept)}
        return self.vocab

    def featurize(
        self,
        refs: Sequence[SampleRef],
        get_record: Callable[[str], Mapping[str, Any] | None],
        value_sets: Sequence[set[str]] | None = None,
    ):
        """Build the sparse presence matrix. Requires a vocabulary.

        ``value_sets`` lets a caller reuse already-extracted value sets;
        re-deriving them means a second full pass over the record cache, which
        dominated the fit time when vocabulary building and featurization each
        did their own.
        """
        from scipy.sparse import csr_matrix

        if not self.vocab:
            raise RuntimeError("build_vocab() must run before featurize()")
        if value_sets is None:
            value_sets = self._values_of(refs, get_record)

        indptr = [0]
        indices: list[int] = []
        for values in value_sets:
            cols = set()
            for value in values:
                col = self.vocab.get(value)
                if col is not None:
                    cols.add(col)
            indices.extend(sorted(cols))
            indptr.append(len(indices))

        data = np.ones(len(indices), dtype=np.float32)
        return csr_matrix(
            (data, np.array(indices, dtype=np.int64), np.array(indptr, dtype=np.int64)),
            shape=(len(refs), len(self.vocab)),
        )

    # -- training ------------------------------------------------------
    def fit(
        self,
        refs: Sequence[SampleRef],
        get_record: Callable[[str], Mapping[str, Any] | None],
        family_names: Sequence[str],
    ) -> dict[str, Any]:
        import lightgbm as lgb

        cfg = self.config
        self.family_names = list(family_names)
        value_sets = self._values_of(refs, get_record)   # one pass over the cache
        self.build_vocab(refs, get_record, value_sets)
        X = self.featurize(refs, get_record, value_sets)
        y = np.array([r.label for r in refs], dtype=np.int8)
        w = np.array([r.weight for r in refs], dtype=np.float32)

        common = dict(
            n_estimators=cfg.n_estimators, learning_rate=cfg.learning_rate,
            num_leaves=cfg.num_leaves, min_child_samples=cfg.min_child_samples,
            subsample=cfg.subsample, subsample_freq=1,
            colsample_bytree=cfg.colsample_bytree,
            random_state=cfg.seed, n_jobs=cfg.n_jobs, verbose=-1,
        )
        self.model_binary = lgb.LGBMClassifier(**common)
        self.model_binary.fit(X, y, sample_weight=w)

        fam_rows = [i for i, r in enumerate(refs)
                    if r.family_index != FAMILY_UNLABELED]
        summary: dict[str, Any] = {
            "n_train": len(refs),
            "n_features": len(self.vocab),
            "n_family_rows": len(fam_rows),
            "n_family_classes": len(self.family_names),
        }
        if fam_rows and len(self.family_names) > 1:
            self.model_family = lgb.LGBMClassifier(
                objective="multiclass", num_class=len(self.family_names), **common)
            self.model_family.fit(
                X[fam_rows],
                np.array([refs[i].family_index for i in fam_rows]),
                sample_weight=w[fam_rows],
            )
        return summary

    # -- inference -----------------------------------------------------
    def predict_binary(self, refs, get_record) -> np.ndarray:
        X = self.featurize(refs, get_record)
        return self.model_binary.predict_proba(X)[:, 1]

    def predict_family(self, refs, get_record) -> np.ndarray:
        X = self.featurize(refs, get_record)
        return self.model_family.predict_proba(X)

    # -- attribution ---------------------------------------------------
    def ranked_values(
        self, head: str = "binary", top_k: int = 5_000
    ) -> list[tuple[str, float]]:
        """Values ranked by gain -- **direction-agnostic**, diagnostics only.

        Do NOT use this to emit candidates. Gain measures how much a feature
        separated the classes in either direction, and empirically the strongest
        separators here are *benign* markers (code-signing certificate strings:
        ``verisign``, ``thawte``, ``microsoft code signing pca``). Those are real
        discriminators and useless as YARA candidates -- a rule built from them
        would match signed software.

        Use :meth:`malware_ranked_values` for candidate emission.
        """
        model = self.model_binary if head == "binary" else self.model_family
        if model is None:
            return []
        gains = model.booster_.feature_importance(importance_type="gain")
        inverse = {i: v for v, i in self.vocab.items()}
        pairs = [(inverse[i], float(g)) for i, g in enumerate(gains)
                 if g > 0 and i in inverse]
        pairs.sort(key=lambda vg: (-vg[1], vg[0]))
        return pairs[:top_k]

    def malware_ranked_values(
        self,
        refs: Sequence[SampleRef],
        get_record: Callable[[str], Mapping[str, Any] | None],
        top_k: int = 5_000,
        max_rows: int = 2_000,
    ) -> list[tuple[str, float]]:
        """Values whose presence pushes toward MALWARE, by mean positive SHAP.

        This is the directional ranking candidate emission needs. SHAP gives a
        signed per-feature contribution, so clipping to positive contributions on
        the malware class keeps only "presence of this means more malicious" and
        discards the benign markers that dominate the gain ranking.

        ``max_rows`` subsamples for tractability; SHAP over 200k sparse features
        is the expensive part, and the ranking is stable well below the full set.
        """
        if self.model_binary is None:
            return []
        import shap

        rows = [r for r in refs if r.label == 1][:max_rows]
        if not rows:
            return []
        X = self.featurize(rows, get_record)
        explainer = shap.TreeExplainer(self.model_binary)
        values = explainer.shap_values(X)
        contrib = np.asarray(values[1] if isinstance(values, list) else values)
        if contrib.ndim == 3:                     # (rows, features, classes)
            contrib = contrib[:, :, 1]
        mean_pos = np.clip(contrib, 0, None).mean(axis=0)

        inverse = {i: v for v, i in self.vocab.items()}
        pairs = [(inverse[i], float(s)) for i, s in enumerate(mean_pos)
                 if s > 0 and i in inverse]
        pairs.sort(key=lambda vs: (-vs[1], vs[0]))
        return pairs[:top_k]

    def family_ranked_values(
        self, family: str, refs, get_record, top_k: int = 500
    ) -> list[tuple[str, float]]:
        """Per-family ranking via SHAP on that family's class output.

        The global gain ranking is family-agnostic; ISB-A needs "what marks THIS
        family", so the per-class SHAP contribution is the right signal.
        """
        if self.model_family is None or family not in self.family_names:
            return []
        import shap

        class_index = self.family_names.index(family)
        X = self.featurize(refs, get_record)
        explainer = shap.TreeExplainer(self.model_family)
        values = explainer.shap_values(X)
        if isinstance(values, list):
            contrib = np.asarray(values[class_index])
        else:
            contrib = np.asarray(values)[:, :, class_index]
        mean_pos = np.clip(contrib, 0, None).mean(axis=0)
        inverse = {i: v for v, i in self.vocab.items()}
        pairs = [(inverse[i], float(s)) for i, s in enumerate(mean_pos)
                 if s > 0 and i in inverse]
        pairs.sort(key=lambda vs: (-vs[1], vs[0]))
        return pairs[:top_k]

    # -- persistence ---------------------------------------------------
    def save(self, out_dir: str) -> dict[str, str]:
        os.makedirs(out_dir, exist_ok=True)
        pkl = os.path.join(out_dir, "model_a.pkl")
        with open(pkl, "wb") as fh:
            pickle.dump({
                "config": self.config,
                "vocab": self.vocab,
                "family_names": self.family_names,
                "model_binary": self.model_binary,
                "model_family": self.model_family,
            }, fh, protocol=pickle.HIGHEST_PROTOCOL)
        meta = os.path.join(out_dir, "model_a.meta.json")
        with open(meta, "w") as fh:
            json.dump({"n_features": len(self.vocab),
                       "n_family_classes": len(self.family_names),
                       "family_names": self.family_names}, fh, indent=2)
        return {"pkl": pkl, "meta": meta}

    @classmethod
    def load(cls, pkl_path: str) -> "StringPresenceClassifier":
        with open(pkl_path, "rb") as fh:
            blob = pickle.load(fh)
        out = cls(blob["config"])
        out.vocab = blob["vocab"]
        out.family_names = blob["family_names"]
        out.model_binary = blob["model_binary"]
        out.model_family = blob["model_family"]
        return out

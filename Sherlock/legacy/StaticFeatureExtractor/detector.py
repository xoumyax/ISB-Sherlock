"""
Layer 1 malware detector — ensemble of EMBER/EMBER2024 + needforspeed.

Both consume the same StaticFeatures object. The ensemble averages their
P(malicious) scores and applies a configurable threshold.

Models are loaded lazily so the extractor module doesn't need them at import.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from .schema import StaticFeatures, FileFormat

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
#  Detector protocol
# ──────────────────────────────────────────────────────────────────────

class Detector(Protocol):
    """A detector takes raw bytes and returns P(malicious) ∈ [0, 1]."""
    name: str

    def predict(self, data: bytes, features: StaticFeatures) -> float: ...


@dataclass
class DetectionResult:
    is_malicious: bool
    probability: float
    threshold: float
    per_model: dict[str, float]
    abstained: bool = False
    reason: str = ""


# ──────────────────────────────────────────────────────────────────────
#  EMBER LightGBM detector
# ──────────────────────────────────────────────────────────────────────

class EmberDetector:
    """
    EMBER-2018 LightGBM detector. Loads a pretrained .txt LightGBM model.

    The official EMBER model is published as `ember_model_2018.txt`
    (~1MB) at https://github.com/elastic/ember. Pass that path here.

    This implementation extracts EMBER's 2381-feature vector lazily.
    """

    name = "ember_lightgbm"

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = Path(model_path) if model_path else None
        self._booster = None
        self._extractor = None

    def _ensure_loaded(self) -> bool:
        if self._booster is not None:
            return True
        if self.model_path is None or not self.model_path.exists():
            logger.warning("EMBER model not configured; detector will abstain")
            return False
        try:
            import lightgbm as lgb
            self._booster = lgb.Booster(model_file=str(self.model_path))
        except ImportError:
            logger.warning("lightgbm not installed; EmberDetector will abstain")
            return False
        except Exception as exc:
            logger.error("EMBER model load failed: %s", exc)
            return False

        try:
            from ember.features import PEFeatureExtractor
            self._extractor = PEFeatureExtractor(feature_version=2)
        except ImportError:
            logger.warning("ember package not installed; EmberDetector will abstain")
            return False
        return True

    def predict(self, data: bytes, features: StaticFeatures) -> float:
        if features.file_type.detected_format != FileFormat.PE:
            # EMBER is PE-only; abstain on other formats by returning 0.5
            return 0.5

        if not self._ensure_loaded():
            return 0.5

        try:
            import numpy as np
            vec = np.array(self._extractor.feature_vector(data), dtype=np.float32)
            score = float(self._booster.predict(vec.reshape(1, -1))[0])
            return max(0.0, min(1.0, score))
        except ImportError:
            logger.warning("numpy not installed; EmberDetector will abstain")
            return 0.5
        except Exception as exc:
            logger.warning("EMBER prediction failed: %s", exc)
            return 0.5


# ──────────────────────────────────────────────────────────────────────
#  EMBER2024 / thrember LightGBM detector
# ──────────────────────────────────────────────────────────────────────

class Ember2024Detector:
    """
    EMBER2024 LightGBM detector using thrember feature version 3.

    Pass a downloaded `.model` artifact from `thrember.download_models()`.
    The actual thrember/lightgbm imports are lazy so this detector can remain
    optional in normal extractor deployments.
    """

    name = "ember2024_lightgbm"

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = Path(model_path) if model_path else None
        self._booster = None
        self._predict_sample = None

    def _ensure_loaded(self) -> bool:
        if self._booster is not None and self._predict_sample is not None:
            return True
        if self.model_path is None or not self.model_path.exists():
            logger.warning("EMBER2024 model not configured; detector will abstain")
            return False
        try:
            import lightgbm as lgb
            import thrember
            self._booster = lgb.Booster(model_file=str(self.model_path))
            self._predict_sample = thrember.predict_sample
        except ImportError:
            logger.warning("lightgbm/thrember not installed; Ember2024Detector will abstain")
            return False
        except Exception as exc:
            logger.error("EMBER2024 model load failed: %s", exc)
            return False
        return True

    def predict(self, data: bytes, features: StaticFeatures) -> float:
        if not self._ensure_loaded():
            return 0.5
        try:
            score = float(self._predict_sample(self._booster, data))
            return max(0.0, min(1.0, score))
        except Exception as exc:
            logger.warning("EMBER2024 prediction failed: %s", exc)
            return 0.5


# ──────────────────────────────────────────────────────────────────────
#  needforspeed detector
# ──────────────────────────────────────────────────────────────────────

class NeedForSpeedDetector:
    """
    Wrapper around the mlsec2020-needforspeed model. The repo trains a
    LightGBM classifier on top of EMBER features tuned for adversarial
    robustness (Fabricio Ceschin et al., MLSEC 2020).

    Pass the path to the saved .pkl/.txt model artifact.
    """

    name = "needforspeed"

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = Path(model_path) if model_path else None
        self._model = None
        self._extractor = None

    def _ensure_loaded(self) -> bool:
        if self._model is not None:
            return True
        if self.model_path is None or not self.model_path.exists():
            logger.warning("needforspeed model not configured; detector will abstain")
            return False
        try:
            import joblib
            self._model = joblib.load(str(self.model_path))
        except ImportError:
            try:
                import pickle
                with open(self.model_path, "rb") as f:
                    self._model = pickle.load(f)
            except Exception as exc:
                logger.error("needforspeed model load failed: %s", exc)
                return False
        except Exception as exc:
            logger.error("needforspeed model load failed: %s", exc)
            return False

        try:
            from ember.features import PEFeatureExtractor
            self._extractor = PEFeatureExtractor(feature_version=2)
        except ImportError:
            logger.warning("ember package required for needforspeed feature extraction")
            return False
        return True

    def predict(self, data: bytes, features: StaticFeatures) -> float:
        if features.file_type.detected_format != FileFormat.PE:
            return 0.5

        if not self._ensure_loaded():
            return 0.5

        try:
            import numpy as np
            vec = np.array(self._extractor.feature_vector(data),
                           dtype=np.float32).reshape(1, -1)
            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba(vec)
                # Assume binary classifier with class 1 = malicious
                if proba.ndim == 2 and proba.shape[1] >= 2:
                    return max(0.0, min(1.0, float(proba[0, 1])))
                return max(0.0, min(1.0, float(proba.ravel()[0])))
            return max(0.0, min(1.0, float(self._model.predict(vec)[0])))
        except ImportError:
            logger.warning("numpy not installed; NeedForSpeedDetector will abstain")
            return 0.5
        except Exception as exc:
            logger.warning("needforspeed prediction failed: %s", exc)
            return 0.5


# ──────────────────────────────────────────────────────────────────────
#  Heuristic fallback (when no ML models are loaded)
# ──────────────────────────────────────────────────────────────────────

class HeuristicDetector:
    """
    Crude heuristic detector for when no ML model is loaded. Looks for
    high-entropy executable sections, suspicious API combinations, and
    macro-bearing Office documents.

    NOT a substitute for the trained models — it's there so the pipeline
    can run end-to-end in environments without the model artifacts.
    """

    name = "heuristic"

    def predict(self, data: bytes, features: StaticFeatures) -> float:
        score = 0.0

        # PE heuristics
        if features.pe_sections:
            n_suspicious = sum(1 for s in features.pe_sections if s.suspicious)
            if n_suspicious > 0:
                score += 0.25 * min(1.0, n_suspicious / 2)

        if features.pe_imports and features.pe_imports.suspicious_apis:
            n = len(features.pe_imports.suspicious_apis)
            score += 0.20 * min(1.0, n / 5)

        # Office heuristics
        if features.office:
            if features.office.has_macros:
                score += 0.30
            if features.office.autoexec_triggers:
                score += 0.25
            if features.office.has_dde:
                score += 0.20
            if features.office.suspicious_keywords:
                score += 0.15 * min(1.0, len(features.office.suspicious_keywords) / 3)

        # PDF heuristics
        if features.pdf:
            if features.pdf.has_javascript and features.pdf.has_openaction:
                score += 0.40
            elif features.pdf.has_javascript:
                score += 0.25
            if features.pdf.has_launch:
                score += 0.30
            if features.pdf.has_embedded_files:
                score += 0.15

        # Script heuristics
        if features.script:
            if features.script.obfuscation_score > 0.6:
                score += 0.35
            if features.script.suspicious_keywords:
                score += 0.20 * min(1.0, len(features.script.suspicious_keywords) / 4)
            if features.script.powershell_flags:
                score += 0.20

        # Universal: very high overall entropy
        if features.byte_stats and features.byte_stats.entropy > 7.5:
            score += 0.10

        return max(0.0, min(1.0, score))


# ──────────────────────────────────────────────────────────────────────
#  Ensemble
# ──────────────────────────────────────────────────────────────────────

class EnsembleDetector:
    """
    Weighted-average ensemble of multiple detectors.

    The default config uses EMBER + needforspeed + heuristic. EMBER and
    needforspeed get equal weight; the heuristic is a backstop with
    lower weight.

    Args:
        detectors: List of (Detector, weight) pairs.
        threshold: Decision threshold on the weighted average score.
    """

    def __init__(
        self,
        detectors: list[tuple[Detector, float]],
        threshold: float = 0.5,
    ):
        if not detectors:
            raise ValueError("At least one detector required")
        self.detectors = detectors
        self.threshold = threshold

    @classmethod
    def default(
        cls,
        ember_model_path: Optional[Path] = None,
        ember2024_model_path: Optional[Path] = None,
        nfs_model_path: Optional[Path] = None,
        threshold: float = 0.5,
    ) -> "EnsembleDetector":
        """
        Standard ensemble: EMBER/EMBER2024 + needforspeed + heuristic backstop.

        If model paths are None or unavailable, those detectors abstain
        (return 0.5) and only the heuristic contributes.
        """
        if ember2024_model_path:
            detectors: list[tuple[Detector, float]] = [
                (Ember2024Detector(ember2024_model_path), 0.55),
                (EmberDetector(ember_model_path), 0.20),
                (NeedForSpeedDetector(nfs_model_path), 0.15),
                (HeuristicDetector(), 0.10),
            ]
        else:
            detectors = [
                (EmberDetector(ember_model_path), 0.45),
                (NeedForSpeedDetector(nfs_model_path), 0.45),
                (HeuristicDetector(), 0.10),
            ]
        return cls(detectors, threshold=threshold)

    def predict(self, data: bytes, features: StaticFeatures) -> DetectionResult:
        per_model: dict[str, float] = {}
        weighted_sum = 0.0
        weight_sum = 0.0
        abstain_count = 0

        for det, weight in self.detectors:
            try:
                score = det.predict(data, features)
            except Exception as exc:
                logger.warning("Detector %s raised: %s", det.name, exc)
                score = 0.5

            per_model[det.name] = score
            # 0.5 from EMBER/NFS means "abstain" (model unavailable / non-PE)
            if score == 0.5 and det.name != "heuristic":
                abstain_count += 1
                continue
            weighted_sum += score * weight
            weight_sum += weight

        if weight_sum == 0.0:
            # All detectors abstained
            return DetectionResult(
                is_malicious=False,
                probability=0.5,
                threshold=self.threshold,
                per_model=per_model,
                abstained=True,
                reason="all detectors abstained",
            )

        prob = weighted_sum / weight_sum
        return DetectionResult(
            is_malicious=prob >= self.threshold,
            probability=prob,
            threshold=self.threshold,
            per_model=per_model,
            abstained=False,
        )

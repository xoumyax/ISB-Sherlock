"""
Three-layer IOC extraction pipeline.

  Layer 1: EnsembleDetector + StaticFeatureModel
  Layer 2: AutoPYara (hex-byte rule generation, external)
  Layer 3: StaticIOCExtractor (structured nuanced features)

Layer 3 always executes first because its structured output feeds the
detector and feature model. Layer 2/rule composition executes if either
gate flags malware-like evidence, or if the caller passes force=True.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, Any

from .schema import StaticFeatures
from .extractor import StaticIOCExtractor
from .detector import EnsembleDetector, DetectionResult
from .feature_model import FeatureAssessment, FeatureModel, HeuristicFeatureModel

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """End-to-end output of the three-layer pipeline."""
    path: str
    verdict: str                                  # "benign" | "malicious" | "forced"
    detection: DetectionResult
    features: Optional[StaticFeatures] = None     # Layer 3 output
    feature_assessment: Optional[FeatureAssessment] = None
    autopyara_rule: Optional[str] = None          # Layer 2 output (raw hex-byte rule)
    autopyara_meta: dict[str, Any] = field(default_factory=dict)
    composed_rule: Optional[str] = None           # Layer 2 + Layer 3 merged
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "verdict": self.verdict,
            "detection": {
                "is_malicious": self.detection.is_malicious,
                "probability": self.detection.probability,
                "threshold": self.detection.threshold,
                "per_model": self.detection.per_model,
                "abstained": self.detection.abstained,
                "reason": self.detection.reason,
            },
            "features": self.features.to_dict() if self.features else None,
            "feature_assessment": (
                self.feature_assessment.to_dict() if self.feature_assessment else None
            ),
            "autopyara_rule": self.autopyara_rule,
            "autopyara_meta": self.autopyara_meta,
            "composed_rule": self.composed_rule,
            "errors": self.errors,
        }


class IOCExtractionPipeline:
    """
    End-to-end pipeline.

    Args:
        detector: A pre-configured EnsembleDetector. If None, a default
                  ensemble with no model paths is used (heuristic only).
        autopyara_factory: A zero-arg callable that returns an AutoPYara
                           instance. Lazy so the import doesn't fail when
                           the package isn't installed.
        autopyara_preset: Preset name for AutoPYara.generate().
        feature_model: Static feature judge/filter. Defaults to the
                       explainable heuristic model.
        use_floss: Pass-through to StaticIOCExtractor.
    """

    def __init__(
        self,
        detector: Optional[EnsembleDetector] = None,
        *,
        autopyara_factory=None,
        autopyara_preset: str = "AutoPYara",
        feature_model: Optional[FeatureModel] = None,
        use_floss: bool = False,
    ):
        self.detector = detector or EnsembleDetector.default()
        self.autopyara_factory = autopyara_factory or _default_autopyara_factory
        self.autopyara_preset = autopyara_preset
        self.feature_model = feature_model or HeuristicFeatureModel()
        self.use_floss = use_floss

    # ──────────────────────────────────────────────────────────────────
    #  Main entry point
    # ──────────────────────────────────────────────────────────────────

    def analyze(
        self,
        path: Union[str, Path],
        *,
        force: bool = False,
        rule_name: Optional[str] = None,
    ) -> PipelineResult:
        """
        Run the full pipeline on a single sample.

        Args:
            path: Sample file path.
            force: If True, skip the Layer 1 gate (caller is sure the sample
                   is malicious).
            rule_name: Name for the generated YARA rule.
        """
        path = Path(path)
        errors: list[str] = []

        # Always run Layer 3 first — its features feed Layer 1
        try:
            extractor = StaticIOCExtractor(path, use_floss=self.use_floss)
            features = extractor.extract()
            data = extractor.data
        except Exception as exc:
            errors.append(f"extraction failed: {exc!r}")
            if isinstance(exc, (FileNotFoundError, ValueError)):
                logger.info("Layer 3 extraction failed for %s: %s", path, exc)
            else:
                logger.warning("Layer 3 extraction failed for %s: %s", path, exc)
            return PipelineResult(
                path=str(path),
                verdict="error",
                detection=DetectionResult(
                    is_malicious=False, probability=0.0, threshold=0.5,
                    per_model={}, abstained=True, reason="extraction failed",
                ),
                errors=errors,
            )

        # Layer 1: detection gate
        detection = self.detector.predict(data, features)
        feature_assessment = self.feature_model.assess(features)

        if not force and not detection.is_malicious and not feature_assessment.is_likely_malware:
            return PipelineResult(
                path=str(path),
                verdict="benign",
                detection=detection,
                features=features,
                feature_assessment=feature_assessment,
                errors=errors,
            )

        verdict = "forced" if force else "malicious"

        # Layer 2: AutoPYara hex-byte rule
        autopyara_rule, autopyara_meta = self._run_autopyara(
            path, rule_name=rule_name or _default_rule_name(features),
            errors=errors,
        )

        # Compose final rule from Layer 2 (hex strings) + Layer 3 (conditions)
        composed = self._compose_rule(
            autopyara_rule=autopyara_rule,
            features=features,
            feature_assessment=feature_assessment,
            rule_name=rule_name or _default_rule_name(features),
        )

        return PipelineResult(
            path=str(path),
            verdict=verdict,
            detection=detection,
            features=features,
            feature_assessment=feature_assessment,
            autopyara_rule=autopyara_rule,
            autopyara_meta=autopyara_meta,
            composed_rule=composed,
            errors=errors,
        )

    # ──────────────────────────────────────────────────────────────────
    #  Layer 2: AutoPYara invocation
    # ──────────────────────────────────────────────────────────────────

    def _run_autopyara(
        self,
        path: Path,
        rule_name: str,
        errors: list[str],
    ) -> tuple[Optional[str], dict[str, Any]]:
        try:
            tool = self.autopyara_factory()
        except Exception as exc:
            errors.append(f"autopyara init: {exc!r}")
            logger.warning("AutoPYara not available: %s", exc)
            return None, {}

        try:
            results = tool.generate(
                input_files=str(path),
                preset=self.autopyara_preset,
                rule_name=rule_name,
                output_format="string",
            )
            rule_string = results.get("rule_string")
            meta = {k: v for k, v in results.items() if k != "rule_string"}
            return rule_string, meta
        except Exception as exc:
            errors.append(f"autopyara generate: {exc!r}")
            logger.warning("AutoPYara generation failed: %s", exc)
            return None, {}

    # ──────────────────────────────────────────────────────────────────
    #  Rule composition: Layer 2 + Layer 3
    # ──────────────────────────────────────────────────────────────────

    def _compose_rule(
        self,
        autopyara_rule: Optional[str],
        features: StaticFeatures,
        feature_assessment: Optional[FeatureAssessment],
        rule_name: str,
    ) -> str:
        """
        Merge AutoPYara's hex-byte rule with the structured-feature
        conditions from Layer 3.

        Strategy:
          - Take AutoPYara's `strings:` block verbatim (hex sequences)
          - Replace its `condition:` block with one that ANDs:
              (any of $hex_*) AND (Layer 3 invariants)
          - Always emit a metadata block populated from features.hashes
        """
        meta_lines = self._build_meta_block(features)
        l3_conditions = (
            feature_assessment.selected_yara_conditions()
            if feature_assessment and feature_assessment.selected_features
            else features.to_yara_conditions()
        )

        # Parse AutoPYara's rule to extract strings block
        strings_block, _ = _split_yara_rule(autopyara_rule) if autopyara_rule else ("", "")

        # Build condition expression
        condition_parts: list[str] = []
        if strings_block.strip():
            # AutoPYara's strings get any-of-them as the primary trigger
            condition_parts.append("any of them")
        # AND structural invariants from Layer 3
        # We pick the most discriminative ones, not all
        l3_picked = _pick_strong_conditions(l3_conditions, features)
        if l3_picked:
            condition_parts.extend(l3_picked)

        if not condition_parts:
            # Last-resort fallback: SHA-256 match
            condition_parts.append(
                f'hash.sha256(0, filesize) == "{features.hashes.sha256}"'
            )

        condition_expr = " and\n        ".join(condition_parts)

        # Imports block — only include what the conditions actually use
        imports: list[str] = []
        joined = " ".join(condition_parts)
        if "pe." in joined or features.pe_header:
            imports.append('import "pe"')
        if "dotnet." in joined:
            imports.append('import "dotnet"')
        if "math.entropy" in joined:
            imports.append('import "math"')
        if "hash." in joined:
            imports.append('import "hash"')

        rule = ("\n".join(imports) + "\n\n") if imports else ""
        rule += f"rule {rule_name} {{\n"
        rule += "    meta:\n"
        rule += meta_lines
        if strings_block.strip():
            rule += "    strings:\n"
            rule += strings_block
        rule += "    condition:\n"
        rule += f"        {condition_expr}\n"
        rule += "}\n"
        return rule

    def _build_meta_block(self, features: StaticFeatures) -> str:
        h = features.hashes
        lines = [
            f'        md5     = "{h.md5}"',
            f'        sha1    = "{h.sha1}"',
            f'        sha256  = "{h.sha256}"',
        ]
        if h.ssdeep:
            lines.append(f'        ssdeep  = "{h.ssdeep}"')
        if h.imphash:
            lines.append(f'        imphash = "{h.imphash}"')
        if h.telfhash:
            lines.append(f'        telfhash = "{h.telfhash}"')
        lines.append(f'        format  = "{features.file_type.detected_format.value}"')
        lines.append(f'        magika  = "{features.file_type.magika}"')
        lines.append('        generator = "StaticIOCExtractor pipeline v1"')
        return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────

def _default_autopyara_factory():
    """Default factory — imports AutoPYara lazily."""
    from autopyara import AutoPYara
    return AutoPYara()


def _default_rule_name(features: StaticFeatures) -> str:
    short = features.hashes.sha256[:12]
    fmt = features.file_type.detected_format.value
    return f"malware_{fmt}_{short}"


def _split_yara_rule(rule_text: str) -> tuple[str, str]:
    """
    Crude split of an existing YARA rule into (strings_body, condition_body).
    Returns ("", "") if parsing fails. We don't need a full YARA parser here —
    AutoPYara's output format is predictable.
    """
    if not rule_text:
        return "", ""
    try:
        s_idx = rule_text.find("strings:")
        c_idx = rule_text.find("condition:", s_idx if s_idx >= 0 else 0)
        if s_idx == -1 or c_idx == -1:
            return "", ""
        strings_body = rule_text[s_idx + len("strings:"):c_idx]
        # Trim trailing indentation that originally preceded `condition:`,
        # so the spliced output doesn't double-indent.
        strings_body = strings_body.rstrip(" \t")
        if not strings_body.endswith("\n"):
            strings_body += "\n"
        # condition body up to the matching closing brace
        cond_body = rule_text[c_idx + len("condition:"):]
        last_brace = cond_body.rfind("}")
        if last_brace != -1:
            cond_body = cond_body[:last_brace]
        return strings_body, cond_body
    except Exception:
        return "", ""


def _pick_strong_conditions(
    conditions: list[str],
    features: StaticFeatures,
) -> list[str]:
    """
    Select the most discriminative Layer 3 conditions to AND into the rule.

    Rule of thumb:
      - imphash: strong family signal, always include if present
      - high-entropy section count: include if any
      - .NET typelib: always include if present
      - SHA-256 match alone is too narrow (hash-based YARA rules don't
        survive recompilation), so we don't AND it as a primary condition;
        it lives in the meta block instead.
    """
    picked: list[str] = []
    for c in conditions:
        if c.startswith("pe.imphash()"):
            picked.append(c)
        elif c.startswith("pe.imports(") or c.startswith("(pe.imports("):
            picked.append(c)
        elif c.startswith("dotnet.typelib"):
            picked.append(c)
        elif "math.entropy" in c:
            picked.append(c)
        elif c.startswith("pe.number_of_sections"):
            # Keep this as a weak structural sanity check
            picked.append(c)
    return picked

"""
Feature-level malware assessment and feature selection.

This module is intentionally transparent: it scores static features with
explainable weights, then ranks the best evidence to feed into YARA/rule
synthesis. A trained classifier or local LLM judge can implement the same
interface later without changing the pipeline output contract.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from .schema import (
    ByteHistogramFeatures,
    FileFormat,
    HashFeatures,
    ImportFeatures,
    PEHeaderFeatures,
    PDFFeatures,
    ScriptFeatures,
    SectionFeature,
    StaticFeatures,
    StringFeatures,
)


@dataclass
class FeatureSignal:
    """One scored signal supporting or weakening a malware assessment."""

    name: str
    category: str
    value: Any
    weight: float
    confidence: float
    reason: str
    yara_condition: str | None = None

    @property
    def score(self) -> float:
        return self.weight * self.confidence

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FeatureAssessment:
    """Model output for feature triage."""

    is_likely_malware: bool
    probability: float
    threshold: float
    selected_features: list[FeatureSignal] = field(default_factory=list)
    supporting_signals: list[FeatureSignal] = field(default_factory=list)
    weak_or_contextual_signals: list[FeatureSignal] = field(default_factory=list)
    verdict: str = "unknown"
    model_name: str = "heuristic_feature_model_v1"
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_likely_malware": self.is_likely_malware,
            "probability": self.probability,
            "threshold": self.threshold,
            "verdict": self.verdict,
            "model_name": self.model_name,
            "selected_features": [s.to_dict() for s in self.selected_features],
            "supporting_signals": [s.to_dict() for s in self.supporting_signals],
            "weak_or_contextual_signals": [s.to_dict() for s in self.weak_or_contextual_signals],
            "rationale": self.rationale,
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), default=str, **kwargs)

    def selected_yara_conditions(self) -> list[str]:
        return [s.yara_condition for s in self.selected_features if s.yara_condition]


class FeatureModel(Protocol):
    name: str

    def assess(self, features: StaticFeatures) -> FeatureAssessment: ...


@dataclass
class FeatureModelTrainingResult:
    """Metadata returned after fitting a trainable static-feature model."""

    model_path: str
    n_samples: int
    n_tokens: int
    score_threshold: float
    score_mean: float
    score_std: float
    model_name: str = "sklearn_one_class_feature_model_v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def feature_tokens(features: StaticFeatures) -> list[str]:
    """
    Convert structured static features into stable token strings.

    These tokens are deliberately shaped like a tiny domain language. They
    preserve family/useful traits such as imports, imphash, section layout,
    script behavior, document triggers, URLs/hosts, and entropy buckets while
    avoiding exact-file hashes that would make a classifier memorize samples.
    """
    tokens: set[str] = set()
    ft = features.file_type
    tokens.add(_tok("file.format", ft.detected_format.value))
    tokens.add(_tok("file.size", _size_bucket(ft.file_size)))
    if ft.magika:
        tokens.add(_tok("file.magika", ft.magika))

    if features.byte_stats:
        tokens.add(_tok("bytes.entropy", _entropy_bucket(features.byte_stats.entropy)))

    _add_pe_tokens(features, tokens)
    _add_elf_tokens(features, tokens)
    _add_macho_tokens(features, tokens)
    _add_script_doc_tokens(features, tokens)
    _add_string_tokens(features, tokens)
    return sorted(tokens)


def iter_static_features_jsonl(path: str | Path) -> Iterable[StaticFeatures]:
    """
    Yield StaticFeatures from a JSONL corpus.

    Each line may either be a raw StaticFeatures dict or an envelope with a
    `features` field plus labels/source metadata.
    """
    with Path(path).open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_no}: {exc}") from exc
            feature_obj = obj.get("features", obj)
            if not isinstance(feature_obj, dict):
                raise ValueError(f"line {line_no} does not contain a feature object")
            yield static_features_from_dict(feature_obj)


def train_one_class_feature_model(
    jsonl_path: str | Path,
    model_out: str | Path,
    *,
    nu: float = 0.05,
    max_features: int = 50000,
    min_df: int = 1,
    max_iter: int = 2000,
    random_state: int = 7,
) -> FeatureModelTrainingResult:
    """
    Train a low-RAM one-class model over feature tokens.

    The JSONL corpus should contain malware samples. The resulting model
    estimates "looks like known malware static features" rather than a final
    benign-vs-malware truth. Adding benign/background samples later should
    use a supervised classifier beside this one-class model.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import SGDOneClassSVM
    except ImportError as exc:
        raise ImportError(
            "Training requires scikit-learn. Install it with `pip install scikit-learn joblib`."
        ) from exc

    docs: list[str] = []
    for features in iter_static_features_jsonl(jsonl_path):
        tokens = feature_tokens(features)
        if tokens:
            docs.append(" ".join(tokens))

    if not docs:
        raise ValueError("training corpus is empty or produced no feature tokens")

    vectorizer = TfidfVectorizer(
        lowercase=False,
        tokenizer=str.split,
        token_pattern=None,
        max_features=max_features,
        min_df=min_df,
    )
    x_train = vectorizer.fit_transform(docs)
    classifier = SGDOneClassSVM(
        nu=nu,
        max_iter=max_iter,
        random_state=random_state,
        tol=1e-3,
    )
    classifier.fit(x_train)

    raw_scores = [float(s) for s in classifier.decision_function(x_train)]
    score_threshold = _percentile(raw_scores, max(0.0, min(50.0, nu * 100.0)))
    score_mean = sum(raw_scores) / len(raw_scores)
    score_std = _stddev(raw_scores, score_mean)

    model = SklearnOneClassFeatureModel(
        vectorizer=vectorizer,
        classifier=classifier,
        score_threshold=score_threshold,
        score_mean=score_mean,
        score_std=score_std,
        training_samples=len(docs),
    )
    model.save(model_out)
    return FeatureModelTrainingResult(
        model_path=str(model_out),
        n_samples=len(docs),
        n_tokens=len(vectorizer.get_feature_names_out()),
        score_threshold=score_threshold,
        score_mean=score_mean,
        score_std=score_std,
    )


class HeuristicFeatureModel:
    """
    Explainable baseline model for malware-likelihood and feature selection.

    The score is intentionally conservative. Hashes are never used to decide
    malware-likelihood, but family-oriented hashes such as imphash can be
    selected as rule features after the sample is judged suspicious.
    """

    name = "heuristic_feature_model_v1"

    def __init__(self, *, threshold: float = 0.45, max_selected: int = 12) -> None:
        self.threshold = threshold
        self.max_selected = max_selected

    def assess(self, features: StaticFeatures) -> FeatureAssessment:
        signals: list[FeatureSignal] = []
        weak: list[FeatureSignal] = []

        self._score_format(features, signals, weak)
        self._score_pe(features, signals, weak)
        self._score_scripts_docs(features, signals, weak)
        self._score_strings(features, signals, weak)
        self._score_byte_stats(features.byte_stats, signals)

        positive = sum(max(0.0, s.score) for s in signals)
        negative = sum(abs(min(0.0, s.score)) for s in signals)
        probability = _clamp(positive / (1.0 + positive + negative))
        is_likely = probability >= self.threshold

        selected = self._select_best_features(features, signals) if is_likely else []
        verdict = "malware_like" if is_likely else "not_enough_malware_evidence"
        rationale = self._build_rationale(probability, selected, signals, weak)
        return FeatureAssessment(
            is_likely_malware=is_likely,
            probability=round(probability, 4),
            threshold=self.threshold,
            selected_features=selected,
            supporting_signals=sorted(signals, key=lambda s: s.score, reverse=True),
            weak_or_contextual_signals=weak,
            verdict=verdict,
            model_name=self.name,
            rationale=rationale,
        )

    def _score_format(self, features: StaticFeatures, signals: list[FeatureSignal], weak: list[FeatureSignal]) -> None:
        ft = features.file_type
        if ft.detected_format == FileFormat.PE:
            weak.append(_signal("format.pe", "format", ft.libmagic, 0.05, 0.5, "Executable PE file; contextual, not malicious alone."))
        elif ft.detected_format in {FileFormat.SCRIPT, FileFormat.OFFICE, FileFormat.PDF}:
            weak.append(_signal("format.document_or_script", "format", ft.detected_format.value, 0.05, 0.5, "Document/script format can carry malware, but format alone is weak."))

    def _score_pe(self, features: StaticFeatures, signals: list[FeatureSignal], weak: list[FeatureSignal]) -> None:
        header = features.pe_header
        imports = features.pe_imports
        sections = features.pe_sections
        resources = features.pe_resources
        hashes = features.hashes

        if imports and imports.suspicious_apis:
            suspicious_count = len(imports.suspicious_apis)
            weight = min(0.55, 0.12 + suspicious_count * 0.045)
            signals.append(_signal(
                "pe.suspicious_apis",
                "imports",
                imports.suspicious_apis,
                weight,
                0.82,
                f"{suspicious_count} suspicious API imports indicate execution, anti-analysis, registry, or dynamic loading behavior.",
                _import_condition(imports.suspicious_apis),
            ))

        if hashes.imphash and imports and imports.n_imports >= 8:
            signals.append(_signal(
                "pe.imphash",
                "imports",
                hashes.imphash,
                0.22,
                0.75,
                "Imphash is a useful family-clustering feature when paired with suspicious imports.",
                f'pe.imphash() == "{hashes.imphash}"',
            ))
        elif hashes.imphash:
            weak.append(_signal("pe.imphash.context", "imports", hashes.imphash, 0.05, 0.4, "Imphash exists but needs behavioral context."))

        suspicious_sections = [s for s in sections if s.suspicious]
        high_entropy_sections = [s for s in sections if s.entropy >= 7.0]
        if suspicious_sections:
            signals.append(_signal(
                "pe.suspicious_sections",
                "sections",
                [_section_value(s) for s in suspicious_sections],
                0.32,
                0.8,
                "Executable/writable or unusual high-entropy sections can indicate packing or shellcode.",
                _section_entropy_condition(sections, suspicious_sections[0]),
            ))
        elif high_entropy_sections:
            weak.append(_signal(
                "pe.high_entropy_sections",
                "sections",
                [_section_value(s) for s in high_entropy_sections],
                0.12,
                0.5,
                "High entropy section exists, but no strong suspicious section pattern was found.",
            ))

        if resources:
            large_resources = [r for r in resources if r.size >= 128 * 1024]
            high_entropy_resources = [r for r in resources if r.entropy >= 6.0 and r.size >= 32 * 1024]
            if high_entropy_resources:
                signals.append(_signal(
                    "pe.high_entropy_resource",
                    "resources",
                    [
                        {
                            "type": r.type,
                            "name": r.name,
                            "size": r.size,
                            "entropy": round(r.entropy, 3),
                            "sha256": r.sha256,
                        }
                        for r in high_entropy_resources[:4]
                    ],
                    0.22 if large_resources else 0.14,
                    0.68,
                    "Large/high-entropy PE resources can hide compressed payloads, images, or embedded data.",
                ))

        if header:
            self._score_pe_header(header, weak)

    def _score_pe_header(self, header: PEHeaderFeatures, weak: list[FeatureSignal]) -> None:
        if header.has_tls:
            weak.append(_signal("pe.has_tls", "header", True, 0.08, 0.45, "TLS callbacks can be abused for early execution, but are not malicious alone."))
        if header.has_debug:
            weak.append(_signal("pe.has_debug", "header", True, -0.05, 0.5, "Debug metadata can indicate normal build artifacts."))
        if not header.is_signed:
            weak.append(_signal("pe.unsigned", "header", True, 0.05, 0.4, "Unsigned executable is contextual, not decisive."))

    def _score_scripts_docs(self, features: StaticFeatures, signals: list[FeatureSignal], weak: list[FeatureSignal]) -> None:
        script = features.script
        if script:
            if script.obfuscation_score >= 0.6:
                signals.append(_signal("script.obfuscation", "script", round(script.obfuscation_score, 3), 0.42, 0.85, "High script obfuscation score."))
            if script.suspicious_keywords:
                signals.append(_signal("script.suspicious_keywords", "script", script.suspicious_keywords, 0.32, 0.78, "Suspicious script keywords indicate download, execution, or evasion behavior."))
            if script.powershell_flags:
                signals.append(_signal("script.powershell_flags", "script", script.powershell_flags, 0.25, 0.78, "PowerShell execution/encoded flags are strong static signals."))

        office = features.office
        if office:
            if office.has_macros:
                signals.append(_signal("office.macros", "office", office.macro_languages, 0.35, 0.78, "Office macros present."))
            if office.autoexec_triggers:
                signals.append(_signal("office.autoexec", "office", office.autoexec_triggers, 0.38, 0.86, "Auto-executing macro triggers present."))
            if office.has_dde:
                signals.append(_signal("office.dde", "office", True, 0.30, 0.8, "DDE usage is a suspicious document execution signal."))

        pdf = features.pdf
        if pdf:
            self._score_pdf(pdf, signals)

    def _score_pdf(self, pdf: PDFFeatures, signals: list[FeatureSignal]) -> None:
        if pdf.has_javascript and pdf.has_openaction:
            signals.append(_signal("pdf.javascript_openaction", "pdf", True, 0.45, 0.88, "PDF JavaScript launched by OpenAction."))
        elif pdf.has_javascript:
            signals.append(_signal("pdf.javascript", "pdf", True, 0.24, 0.7, "PDF JavaScript present."))
        if pdf.has_launch:
            signals.append(_signal("pdf.launch", "pdf", True, 0.34, 0.82, "PDF Launch action present."))
        if pdf.has_embedded_files:
            signals.append(_signal("pdf.embedded_files", "pdf", pdf.embedded_files, 0.22, 0.7, "PDF contains embedded files."))

    def _score_strings(self, features: StaticFeatures, signals: list[FeatureSignal], weak: list[FeatureSignal]) -> None:
        strings = features.strings
        if not strings:
            return

        suspicious_paths = _suspicious_paths(strings)
        if suspicious_paths:
            signals.append(_signal(
                "strings.suspicious_paths",
                "strings",
                suspicious_paths,
                0.24,
                0.72,
                "String table contains execution/tooling paths often useful for detection context.",
            ))

        if strings.urls:
            signals.append(_signal(
                "strings.urls",
                "strings",
                strings.urls[:8],
                0.26,
                0.74,
                "Embedded URLs are useful network IOCs when not generic.",
            ))
        if strings.ips:
            public_ips = [ip for ip in strings.ips if not _is_non_routable_ip(ip)]
            if public_ips:
                signals.append(_signal(
                    "strings.public_ips",
                    "strings",
                    public_ips[:8],
                    0.22,
                    0.68,
                    "Embedded public IPs can indicate network infrastructure.",
                ))
            else:
                weak.append(_signal("strings.non_routable_ips", "strings", strings.ips, 0.02, 0.2, "Only non-routable/loopback IPs found."))

        if strings.registry_keys:
            signals.append(_signal(
                "strings.registry_keys",
                "strings",
                strings.registry_keys[:8],
                0.22,
                0.68,
                "Registry key strings can support persistence or configuration detection.",
            ))

    def _score_byte_stats(self, byte_stats: ByteHistogramFeatures | None, signals: list[FeatureSignal]) -> None:
        if byte_stats and byte_stats.entropy >= 7.5:
            signals.append(_signal("bytes.high_entropy", "bytes", round(byte_stats.entropy, 3), 0.18, 0.65, "High whole-file entropy can indicate packing or encryption."))

    def _select_best_features(self, features: StaticFeatures, signals: list[FeatureSignal]) -> list[FeatureSignal]:
        candidates = [s for s in signals if s.score > 0 and s.category != "format"]
        candidates.sort(key=lambda s: (s.yara_condition is not None, s.score), reverse=True)

        selected: list[FeatureSignal] = []
        seen_names: set[str] = set()
        for signal in candidates:
            if signal.name in seen_names:
                continue
            selected.append(signal)
            seen_names.add(signal.name)
            if len(selected) >= self.max_selected:
                break

        # If a PE looks malicious and has no condition-bearing signal yet,
        # add stable structural features from StaticFeatures.to_yara_conditions().
        if not any(s.yara_condition for s in selected):
            for cond in features.to_yara_conditions():
                selected.append(_signal(
                    "structured.yara_condition",
                    "structured",
                    cond,
                    0.12,
                    0.6,
                    "Fallback structured YARA condition from extracted features.",
                    cond,
                ))
                if len(selected) >= self.max_selected:
                    break
        return selected

    def _build_rationale(
        self,
        probability: float,
        selected: list[FeatureSignal],
        signals: list[FeatureSignal],
        weak: list[FeatureSignal],
    ) -> list[str]:
        rationale = [
            f"Feature model probability={probability:.4f}, threshold={self.threshold:.2f}.",
        ]
        top = sorted(signals, key=lambda s: s.score, reverse=True)[:4]
        if top:
            rationale.append("Top positive signals: " + "; ".join(f"{s.name} ({s.score:.2f})" for s in top) + ".")
        if selected:
            rationale.append("Selected detection features: " + "; ".join(s.name for s in selected[:6]) + ".")
        elif weak:
            rationale.append("Only weak/contextual signals were found; do not promote these to a malware rule without more evidence.")
        return rationale


class SklearnOneClassFeatureModel:
    """
    Trainable one-class model over static-feature tokens.

    This model is intentionally small and local: TF-IDF tokenization plus a
    linear SGD one-class SVM. It is suitable for "similar to known malware"
    scoring and feature filtering, while the heuristic model remains the
    transparent fallback and YARA-condition source.
    """

    name = "sklearn_one_class_feature_model_v1"

    def __init__(
        self,
        *,
        vectorizer: Any,
        classifier: Any,
        score_threshold: float,
        score_mean: float = 0.0,
        score_std: float = 1.0,
        training_samples: int = 0,
        threshold: float = 0.5,
        max_selected: int = 12,
    ) -> None:
        self.vectorizer = vectorizer
        self.classifier = classifier
        self.score_threshold = score_threshold
        self.score_mean = score_mean
        self.score_std = score_std if score_std > 1e-9 else 1.0
        self.training_samples = training_samples
        self.threshold = threshold
        self.max_selected = max_selected

    @classmethod
    def load(cls, path: str | Path, *, threshold: float = 0.5, max_selected: int = 12) -> "SklearnOneClassFeatureModel":
        try:
            import joblib
        except ImportError as exc:
            raise ImportError(
                "Loading a trained feature model requires joblib. Install it with `pip install joblib`."
            ) from exc

        payload = joblib.load(path)
        if not isinstance(payload, dict):
            raise ValueError("feature model file is not a recognized StaticIOCExtractor payload")
        return cls(
            vectorizer=payload["vectorizer"],
            classifier=payload["classifier"],
            score_threshold=float(payload["score_threshold"]),
            score_mean=float(payload.get("score_mean", 0.0)),
            score_std=float(payload.get("score_std", 1.0)),
            training_samples=int(payload.get("training_samples", 0)),
            threshold=threshold,
            max_selected=max_selected,
        )

    def save(self, path: str | Path) -> None:
        try:
            import joblib
        except ImportError as exc:
            raise ImportError(
                "Saving a trained feature model requires joblib. Install it with `pip install joblib`."
            ) from exc

        payload = {
            "model_name": self.name,
            "vectorizer": self.vectorizer,
            "classifier": self.classifier,
            "score_threshold": self.score_threshold,
            "score_mean": self.score_mean,
            "score_std": self.score_std,
            "training_samples": self.training_samples,
        }
        joblib.dump(payload, path)

    def assess(self, features: StaticFeatures) -> FeatureAssessment:
        tokens = feature_tokens(features)
        doc = " ".join(tokens)
        x_row = self.vectorizer.transform([doc])
        raw_score = float(self.classifier.decision_function(x_row)[0])
        normalized = (raw_score - self.score_threshold) / self.score_std
        probability = _sigmoid(normalized)
        is_likely = probability >= self.threshold

        model_signals = self._rank_model_signals(x_row)
        heuristic = HeuristicFeatureModel(max_selected=self.max_selected).assess(features)
        selected = self._merge_selected_features(heuristic, model_signals) if is_likely else []

        support_score = _signal(
            "model.one_class_score",
            "model",
            {
                "raw_score": round(raw_score, 6),
                "training_threshold": round(self.score_threshold, 6),
                "training_samples": self.training_samples,
            },
            0.35,
            probability,
            "Trained one-class static-feature score; calibrated against malware training scores.",
        )
        supporting = [support_score] + model_signals[:20] + heuristic.supporting_signals
        verdict = "malware_like" if is_likely else "not_enough_malware_evidence"
        rationale = [
            (
                f"One-class feature model probability={probability:.4f}, "
                f"threshold={self.threshold:.2f}, raw_score={raw_score:.4f}."
            ),
            "Score means similarity to known-malware static features, not standalone ground truth.",
        ]
        if selected:
            rationale.append("Selected detection features: " + "; ".join(s.name for s in selected[:6]) + ".")
        elif heuristic.weak_or_contextual_signals:
            rationale.append("Model did not meet threshold; weak/contextual signals remain available for analyst review.")

        return FeatureAssessment(
            is_likely_malware=is_likely,
            probability=round(probability, 4),
            threshold=self.threshold,
            selected_features=selected,
            supporting_signals=supporting,
            weak_or_contextual_signals=heuristic.weak_or_contextual_signals,
            verdict=verdict,
            model_name=self.name,
            rationale=rationale,
        )

    def _rank_model_signals(self, x_row: Any) -> list[FeatureSignal]:
        try:
            feature_names = self.vectorizer.get_feature_names_out()
        except Exception:
            return []

        coef = getattr(self.classifier, "coef_", None)
        if coef is None:
            return []

        row = x_row.tocoo()
        ranked: list[tuple[float, str]] = []
        for idx, value in zip(row.col, row.data):
            try:
                weight = float(coef[0][idx])
            except Exception:
                continue
            contribution = float(value) * weight
            if contribution <= 0:
                continue
            ranked.append((contribution, str(feature_names[idx])))

        if not ranked:
            for idx, value in zip(row.col, row.data):
                ranked.append((float(value), str(feature_names[idx])))

        ranked.sort(key=lambda item: (round(item[0], 8), _token_priority(item[1]), item[1]), reverse=True)
        signals: list[FeatureSignal] = []
        for contribution, token in ranked[: self.max_selected * 2]:
            signals.append(_signal(
                name=f"model.token.{token.split(':', 1)[0]}",
                category=token.split(".", 1)[0],
                value=token,
                weight=min(0.4, contribution),
                confidence=0.75,
                reason="Model-ranked static feature token from the trained one-class classifier.",
            ))
        return signals

    def _merge_selected_features(
        self,
        heuristic: FeatureAssessment,
        model_signals: list[FeatureSignal],
    ) -> list[FeatureSignal]:
        selected: list[FeatureSignal] = []
        seen: set[str] = set()
        for signal in heuristic.selected_features + model_signals:
            key = f"{signal.name}:{signal.value}"
            if key in seen:
                continue
            selected.append(signal)
            seen.add(key)
            if len(selected) >= self.max_selected:
                break
        return selected


class LMFeatureModel:
    """
    LM-guided feature model.

    Uses YaraDocAssistant (FAISS + local LM) to refine YARA conditions for the
    top signals selected by the heuristic model.  Falls back gracefully to the
    heuristic assessment when the LM is not available.

    Typical usage::

        from YaraGuide import YaraDocAssistant
        from StaticFeatureExtractor.feature_model import LMFeatureModel

        assistant = YaraDocAssistant()          # loads once
        model     = LMFeatureModel(assistant)
        result    = model.assess(features)
        print(result.selected_yara_conditions())

    Args:
        assistant:   A YaraDocAssistant instance (or any object with a
                     ``query(question: str) -> str`` method).
        base_model:  Base feature model for initial scoring.  Defaults to
                     HeuristicFeatureModel.
        max_queries: Maximum number of LM queries per sample (each query
                     adds latency).
    """

    name = "lm_feature_model_v1"

    def __init__(
        self,
        assistant: Any,
        base_model: "FeatureModel | None" = None,
        *,
        max_queries: int = 6,
        threshold: float = 0.45,
        max_selected: int = 12,
    ) -> None:
        self.assistant = assistant
        self.base = base_model or HeuristicFeatureModel(
            threshold=threshold,
            max_selected=max_selected,
        )
        self.max_queries = max_queries

    def assess(self, features: StaticFeatures) -> FeatureAssessment:
        base = self.base.assess(features)
        if not base.is_likely_malware:
            return base

        refined_signals: list[FeatureSignal] = []
        queries_used = 0
        for signal in base.selected_features:
            if queries_used >= self.max_queries:
                refined_signals.append(signal)
                continue
            if signal.yara_condition:
                refined = self._refine_condition(signal)
                refined_signals.append(refined)
                queries_used += 1
            else:
                refined_signals.append(signal)

        return FeatureAssessment(
            is_likely_malware=base.is_likely_malware,
            probability=base.probability,
            threshold=base.threshold,
            selected_features=refined_signals,
            supporting_signals=base.supporting_signals,
            weak_or_contextual_signals=base.weak_or_contextual_signals,
            verdict=base.verdict,
            model_name=self.name,
            rationale=base.rationale + [
                f"LM refinement applied to {queries_used} signal(s).",
            ],
        )

    def _refine_condition(self, signal: FeatureSignal) -> FeatureSignal:
        """Ask the LM assistant if the heuristic YARA condition is correct."""
        question = (
            f"In YARA, is this condition valid and well-formed for the {signal.category} category?\n"
            f"  {signal.yara_condition}\n"
            f"If yes, confirm. If not, provide the corrected YARA expression only."
        )
        try:
            answer = self.assistant.query(question)
        except Exception:
            return signal

        answer = answer.strip()
        if not answer or answer.lower().startswith("yes"):
            return signal

        # Extract first code-like line from the answer as the corrected condition
        lines = [ln.strip() for ln in answer.splitlines() if ln.strip()]
        candidate = None
        for ln in lines:
            # Heuristic: a YARA condition line contains parens, dots, or quotes
            if any(c in ln for c in ("(", ".", '"', "==")):
                candidate = ln.strip("`\"'")
                break

        if candidate and candidate != signal.yara_condition:
            return FeatureSignal(
                name=signal.name,
                category=signal.category,
                value=signal.value,
                weight=signal.weight,
                confidence=signal.confidence * 0.9,
                reason=signal.reason + f" [LM-refined from: {signal.yara_condition}]",
                yara_condition=candidate,
            )
        return signal


def assessment_from_features_json(path: str | Path, *, threshold: float = 0.45) -> FeatureAssessment:
    """Load a StaticFeatures JSON dump and run the default feature model."""
    features = static_features_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    return HeuristicFeatureModel(threshold=threshold).assess(features)


def static_features_from_dict(data: dict[str, Any]) -> StaticFeatures:
    """Rehydrate StaticFeatures from a JSON/dict dump."""
    from .schema import (
        DotNetFeatures,
        ELFHeaderFeatures,
        ELFSymbolFeatures,
        ExportFeatures,
        FileTypeFeatures,
        ImportFeatures,
        MachOHeaderFeatures,
        OfficeFeatures,
        PDFFeatures,
        ResourceFeature,
        ScriptFeatures,
    )

    return StaticFeatures(
        path=data["path"],
        hashes=HashFeatures(**data["hashes"]),
        file_type=FileTypeFeatures(
            **{
                **data["file_type"],
                "detected_format": FileFormat(data["file_type"]["detected_format"]),
            }
        ),
        byte_stats=ByteHistogramFeatures(**data["byte_stats"]) if data.get("byte_stats") else None,
        strings=StringFeatures(**data["strings"]) if data.get("strings") else None,
        pe_header=PEHeaderFeatures(**data["pe_header"]) if data.get("pe_header") else None,
        pe_sections=[SectionFeature(**s) for s in data.get("pe_sections", [])],
        pe_imports=ImportFeatures(**data["pe_imports"]) if data.get("pe_imports") else None,
        pe_exports=ExportFeatures(**data["pe_exports"]) if data.get("pe_exports") else None,
        pe_resources=[ResourceFeature(**r) for r in data.get("pe_resources", [])],
        dotnet=DotNetFeatures(**data["dotnet"]) if data.get("dotnet") else None,
        elf_header=ELFHeaderFeatures(**data["elf_header"]) if data.get("elf_header") else None,
        elf_sections=[SectionFeature(**s) for s in data.get("elf_sections", [])],
        elf_symbols=ELFSymbolFeatures(**data["elf_symbols"]) if data.get("elf_symbols") else None,
        macho_header=MachOHeaderFeatures(**data["macho_header"]) if data.get("macho_header") else None,
        macho_sections=[SectionFeature(**s) for s in data.get("macho_sections", [])],
        script=ScriptFeatures(**data["script"]) if data.get("script") else None,
        office=OfficeFeatures(**data["office"]) if data.get("office") else None,
        pdf=PDFFeatures(**data["pdf"]) if data.get("pdf") else None,
        parse_errors=list(data.get("parse_errors", [])),
    )


def _add_pe_tokens(features: StaticFeatures, tokens: set[str]) -> None:
    header = features.pe_header
    imports = features.pe_imports
    hashes = features.hashes

    if hashes.imphash:
        tokens.add(_tok("pe.imphash", hashes.imphash))
    if hashes.rich_pv_hash:
        tokens.add(_tok("pe.rich_pv_hash", hashes.rich_pv_hash))

    if header:
        tokens.add(_tok("pe.machine", header.machine))
        tokens.add(_tok("pe.subsystem", header.subsystem))
        tokens.add(_tok("pe.sections.count", header.n_sections))
        tokens.add(_tok("pe.signed", header.is_signed))
        tokens.add(_tok("pe.tls", header.has_tls))
        tokens.add(_tok("pe.debug", header.has_debug))
        tokens.add(_tok("pe.resources", header.has_resources))
        tokens.add(_tok("pe.relocations", header.has_relocations))
        if header.timestamp:
            tokens.add(_tok("pe.timestamp.year_bucket", _timestamp_bucket(header.timestamp)))

    if imports:
        tokens.add(_tok("pe.import.count", _count_bucket(imports.n_imports)))
        for dll in imports.dlls[:64]:
            tokens.add(_tok("pe.import.dll", dll))
        for item in imports.functions[:256]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                dll, func = str(item[0]), str(item[1])
                tokens.add(_tok("pe.import.api", f"{dll}!{func}"))
        for api in imports.suspicious_apis[:128]:
            tokens.add(_tok("pe.import.suspicious", api))

    for section in features.pe_sections[:32]:
        tokens.add(_tok("pe.section.name", section.name))
        tokens.add(_tok("pe.section.size", _size_bucket(section.raw_size)))
        tokens.add(_tok("pe.section.entropy", _entropy_bucket(section.entropy)))
        if section.is_executable:
            tokens.add(_tok("pe.section.executable", section.name))
        if section.is_writable:
            tokens.add(_tok("pe.section.writable", section.name))
        if section.suspicious:
            tokens.add(_tok("pe.section.suspicious", section.name))

    for resource in features.pe_resources[:64]:
        tokens.add(_tok("pe.resource.type", resource.type))
        tokens.add(_tok("pe.resource.size", _size_bucket(resource.size)))
        tokens.add(_tok("pe.resource.entropy", _entropy_bucket(resource.entropy)))

    if features.dotnet:
        dotnet = features.dotnet
        tokens.add(_tok("dotnet.present", True))
        tokens.add(_tok("dotnet.types", _count_bucket(dotnet.n_types)))
        tokens.add(_tok("dotnet.methods", _count_bucket(dotnet.n_methods)))
        for stream in dotnet.streams[:32]:
            tokens.add(_tok("dotnet.stream", stream))
        if dotnet.assembly_name:
            tokens.add(_tok("dotnet.assembly", dotnet.assembly_name))
        if dotnet.typelib_id:
            tokens.add(_tok("dotnet.typelib", dotnet.typelib_id))


def _add_elf_tokens(features: StaticFeatures, tokens: set[str]) -> None:
    header = features.elf_header
    symbols = features.elf_symbols
    if header:
        tokens.add(_tok("elf.machine", header.machine))
        tokens.add(_tok("elf.type", header.file_type))
        tokens.add(_tok("elf.sections.count", header.n_sections))
        tokens.add(_tok("elf.segments.count", header.n_segments))
        tokens.add(_tok("elf.stripped", header.is_stripped))
        tokens.add(_tok("elf.dynamic", header.has_dynamic))
        if header.interpreter:
            tokens.add(_tok("elf.interpreter", header.interpreter))
    if symbols:
        if symbols.telfhash:
            tokens.add(_tok("elf.telfhash", symbols.telfhash))
        tokens.add(_tok("elf.symbols.count", _count_bucket(symbols.n_symbols)))
        for lib in symbols.imported_libraries[:64]:
            tokens.add(_tok("elf.import.lib", lib))
        for func in symbols.imported_functions[:128]:
            tokens.add(_tok("elf.import.func", func))
    for section in features.elf_sections[:32]:
        tokens.add(_tok("elf.section.name", section.name))
        tokens.add(_tok("elf.section.entropy", _entropy_bucket(section.entropy)))


def _add_macho_tokens(features: StaticFeatures, tokens: set[str]) -> None:
    header = features.macho_header
    if header:
        tokens.add(_tok("macho.cpu", header.cpu_type))
        tokens.add(_tok("macho.file_type", header.file_type))
        tokens.add(_tok("macho.commands.count", header.n_commands))
        tokens.add(_tok("macho.fat", header.is_fat))
        tokens.add(_tok("macho.signed", header.is_signed))
        for flag in header.flags[:64]:
            tokens.add(_tok("macho.flag", flag))
    if features.hashes.machoc_hash:
        tokens.add(_tok("macho.hash", features.hashes.machoc_hash))
    for section in features.macho_sections[:32]:
        tokens.add(_tok("macho.section.name", section.name))
        tokens.add(_tok("macho.section.entropy", _entropy_bucket(section.entropy)))


def _add_script_doc_tokens(features: StaticFeatures, tokens: set[str]) -> None:
    script = features.script
    if script:
        tokens.add(_tok("script.language", script.language))
        tokens.add(_tok("script.lines", _count_bucket(script.line_count)))
        tokens.add(_tok("script.entropy", _entropy_bucket(script.entropy)))
        tokens.add(_tok("script.obfuscation", _score_bucket(script.obfuscation_score)))
        tokens.add(_tok("script.base64.count", _count_bucket(len(script.base64_blobs))))
        for keyword in script.suspicious_keywords[:64]:
            tokens.add(_tok("script.keyword", keyword))
        for flag in script.powershell_flags[:32]:
            tokens.add(_tok("script.powershell_flag", flag))
        for url in script.urls[:32]:
            host = _url_host(url)
            if host:
                tokens.add(_tok("script.url.host", host))

    office = features.office
    if office:
        tokens.add(_tok("office.format", office.file_format))
        tokens.add(_tok("office.macros", office.has_macros))
        tokens.add(_tok("office.external_refs", office.has_external_refs))
        tokens.add(_tok("office.dde", office.has_dde))
        for lang in office.macro_languages[:16]:
            tokens.add(_tok("office.macro_language", lang))
        for keyword in office.suspicious_keywords[:64]:
            tokens.add(_tok("office.keyword", keyword))
        for trigger in office.autoexec_triggers[:32]:
            tokens.add(_tok("office.autoexec", trigger))

    pdf = features.pdf
    if pdf:
        tokens.add(_tok("pdf.javascript", pdf.has_javascript))
        tokens.add(_tok("pdf.embedded_files", pdf.has_embedded_files))
        tokens.add(_tok("pdf.openaction", pdf.has_openaction))
        tokens.add(_tok("pdf.launch", pdf.has_launch))
        tokens.add(_tok("pdf.forms", pdf.has_forms))
        tokens.add(_tok("pdf.pages", _count_bucket(pdf.n_pages)))
        for keyword in pdf.suspicious_keywords[:64]:
            tokens.add(_tok("pdf.keyword", keyword))


def _add_string_tokens(features: StaticFeatures, tokens: set[str]) -> None:
    strings = features.strings
    if not strings:
        return
    tokens.add(_tok("strings.count", _count_bucket(strings.n_strings)))
    tokens.add(_tok("strings.entropy", _entropy_bucket(strings.entropy)))
    tokens.add(_tok("strings.printable_ratio", _score_bucket(strings.printable_ratio)))
    for url in strings.urls[:64]:
        host = _url_host(url)
        if host:
            tokens.add(_tok("strings.url.host", host))
    for path in strings.paths[:64]:
        tokens.add(_tok("strings.path.leaf", _path_leaf(path)))
        if path in _suspicious_paths(strings):
            tokens.add(_tok("strings.path.suspicious", path))
    for key in strings.registry_keys[:64]:
        tokens.add(_tok("strings.registry.root", _registry_root(key)))
        tokens.add(_tok("strings.registry.key", key))
    for ip in strings.ips[:64]:
        if _is_non_routable_ip(ip):
            tokens.add(_tok("strings.ip.scope", "private_or_loopback"))
        else:
            tokens.add(_tok("strings.ip.public", ip))


def _tok(prefix: str, value: Any) -> str:
    return f"{prefix}:{_normalize_token_value(value)}"


def _normalize_token_value(value: Any) -> str:
    text = str(value).strip().lower()
    text = text.replace("\\", "/")
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^a-z0-9_./:!@{}$+-]+", "_", text)
    return text.strip("_") or "empty"


def _size_bucket(size: int | float) -> str:
    size = int(size)
    if size <= 0:
        return "empty"
    if size < 1024:
        return "<1kb"
    if size < 16 * 1024:
        return "1kb_16kb"
    if size < 128 * 1024:
        return "16kb_128kb"
    if size < 1024 * 1024:
        return "128kb_1mb"
    if size < 10 * 1024 * 1024:
        return "1mb_10mb"
    return ">=10mb"


def _count_bucket(count: int | float) -> str:
    count = int(count)
    if count <= 0:
        return "0"
    if count == 1:
        return "1"
    if count <= 4:
        return "2_4"
    if count <= 16:
        return "5_16"
    if count <= 64:
        return "17_64"
    if count <= 256:
        return "65_256"
    return ">256"


def _entropy_bucket(entropy: float) -> str:
    if entropy < 2.0:
        return "very_low"
    if entropy < 4.0:
        return "low"
    if entropy < 6.0:
        return "medium"
    if entropy < 7.2:
        return "high"
    return "very_high"


def _score_bucket(score: float) -> str:
    if score < 0.2:
        return "very_low"
    if score < 0.4:
        return "low"
    if score < 0.6:
        return "medium"
    if score < 0.8:
        return "high"
    return "very_high"


def _timestamp_bucket(timestamp: int) -> str:
    # PE timestamps are seconds since epoch; keep only coarse year buckets.
    year = 1970 + int(timestamp // 31557600)
    if year < 2000:
        return "<2000"
    if year > 2035:
        return ">2035"
    return str(year)


def _url_host(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname


def _path_leaf(path: str) -> str:
    normalized = path.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] or normalized


def _registry_root(key: str) -> str:
    key = key.replace("/", "\\")
    return key.split("\\", 1)[0]


def _token_priority(token: str) -> int:
    if ".suspicious" in token:
        return 100
    if any(part in token for part in ("imphash", "telfhash", "machoc_hash", "rich_pv_hash")):
        return 90
    if any(part in token for part in ("import.api", "script.keyword", "office.autoexec", "pdf.openaction")):
        return 80
    if any(part in token for part in ("url.host", "ip.public", "registry.key")):
        return 70
    if any(part in token for part in ("resource.entropy", "section.entropy", "bytes.entropy")):
        return 60
    if any(part in token for part in ("path.suspicious", "powershell_flag", "base64")):
        return 55
    if any(part in token for part in ("printable_ratio", ".count:", ".signed:", ".debug:")):
        return 10
    return 30


def _signal(
    name: str,
    category: str,
    value: Any,
    weight: float,
    confidence: float,
    reason: str,
    yara_condition: str | None = None,
) -> FeatureSignal:
    return FeatureSignal(
        name=name,
        category=category,
        value=value,
        weight=weight,
        confidence=confidence,
        reason=reason,
        yara_condition=yara_condition,
    )


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * (percentile / 100.0)
    low = int(math.floor(pos))
    high = int(math.ceil(pos))
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def _stddev(values: list[float], mean: float) -> float:
    if len(values) <= 1:
        return 1.0
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(max(variance, 1e-12))


def _section_value(section: SectionFeature) -> dict[str, Any]:
    return {
        "name": section.name,
        "raw_size": section.raw_size,
        "entropy": round(section.entropy, 3),
        "characteristics": section.characteristics,
        "md5": section.md5,
    }


def _section_entropy_condition(sections: list[SectionFeature], section: SectionFeature) -> str | None:
    try:
        idx = sections.index(section)
    except ValueError:
        return None
    return f"math.entropy(pe.sections[{idx}].raw_data_offset, pe.sections[{idx}].raw_data_size) > 7.0"


def _import_condition(suspicious_apis: list[str]) -> str | None:
    if not suspicious_apis:
        return None
    parts: list[str] = []
    for api in suspicious_apis[:6]:
        if "!" not in api:
            continue
        dll, func = api.split("!", 1)
        parts.append(f'pe.imports("{dll}", "{func}")')
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return "(" + " or ".join(parts) + ")"


def _suspicious_paths(strings: StringFeatures) -> list[str]:
    out: list[str] = []
    interesting = ("cmd.exe", "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "\\appdata\\", "\\temp\\")
    for path in strings.paths:
        low = path.lower()
        if any(token in low for token in interesting):
            out.append(path)
    return out[:8]


def _is_non_routable_ip(ip: str) -> bool:
    if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
        return True
    if ip == "0.0.0.0" or ip == "255.255.255.255":
        return True
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            first, second = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        return first == 172 and 16 <= second <= 31
    return False

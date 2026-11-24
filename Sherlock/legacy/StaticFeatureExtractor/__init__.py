"""
StaticIOCExtractor — SOTA static feature extractor for malware IOC extraction.

Three layers:
    1. Detection ensemble + static feature model
    2. AutoPYara hex-byte rule generation (external)
    3. Structured static feature extraction (this package)

Public API:
    StaticIOCExtractor        — the extractor itself
    extract                   — one-shot convenience wrapper
    StaticFeatures            — typed output container
    EnsembleDetector          — Layer 1 detection
    HeuristicFeatureModel     — explainable static feature judge
    SklearnOneClassFeatureModel — trainable local static feature judge
    IOCExtractionPipeline     — full three-layer pipeline
"""
from .extractor import StaticIOCExtractor, extract
from .schema import (
    StaticFeatures, FileFormat, HashFeatures, FileTypeFeatures,
    SectionFeature, PEHeaderFeatures, ImportFeatures, ExportFeatures,
    ResourceFeature, DotNetFeatures, ELFHeaderFeatures, ELFSymbolFeatures,
    MachOHeaderFeatures, ScriptFeatures, OfficeFeatures, PDFFeatures,
    StringFeatures, ByteHistogramFeatures,
)
from .detector import (
    EnsembleDetector, EmberDetector, Ember2024Detector, NeedForSpeedDetector,
    HeuristicDetector, DetectionResult,
)
from .ember2024 import (
    Ember2024Plan, VALID_EMBER2024_FILE_TYPES, VALID_EMBER2024_SPLITS,
    download_ember2024_dataset, download_ember2024_models,
    ember2024_download_plan, read_ember2024_vectorized_features,
    vectorize_ember2024_dataset,
)
from .feature_model import (
    FeatureAssessment, FeatureModel, FeatureSignal, HeuristicFeatureModel,
    LMFeatureModel, SklearnOneClassFeatureModel, FeatureModelTrainingResult,
    assessment_from_features_json, feature_tokens, iter_static_features_jsonl,
    static_features_from_dict, train_one_class_feature_model,
)
from .ember_feature_model import EmberFeatureModel
from .feature_to_iocs import features_to_ioc_dicts, features_to_prompt_kwargs
from .pipeline import IOCExtractionPipeline, PipelineResult

__all__ = [
    "StaticIOCExtractor", "extract", "StaticFeatures", "FileFormat",
    "HashFeatures", "FileTypeFeatures", "SectionFeature", "PEHeaderFeatures",
    "ImportFeatures", "ExportFeatures", "ResourceFeature", "DotNetFeatures",
    "ELFHeaderFeatures", "ELFSymbolFeatures", "MachOHeaderFeatures",
    "ScriptFeatures", "OfficeFeatures", "PDFFeatures", "StringFeatures",
    "ByteHistogramFeatures", "EnsembleDetector", "EmberDetector",
    "Ember2024Detector", "NeedForSpeedDetector", "HeuristicDetector", "DetectionResult",
    "Ember2024Plan", "VALID_EMBER2024_FILE_TYPES", "VALID_EMBER2024_SPLITS",
    "download_ember2024_dataset", "download_ember2024_models",
    "ember2024_download_plan", "read_ember2024_vectorized_features",
    "vectorize_ember2024_dataset",
    "FeatureAssessment", "FeatureModel", "FeatureSignal",
    "HeuristicFeatureModel", "LMFeatureModel", "SklearnOneClassFeatureModel",
    "FeatureModelTrainingResult", "assessment_from_features_json",
    "feature_tokens", "iter_static_features_jsonl", "static_features_from_dict",
    "train_one_class_feature_model",
    "EmberFeatureModel",
    "features_to_ioc_dicts", "features_to_prompt_kwargs",
    "IOCExtractionPipeline", "PipelineResult",
]

__version__ = "1.0.0"

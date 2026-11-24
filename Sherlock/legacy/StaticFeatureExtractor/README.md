# StaticFeatureExtractor

Static feature extractor for malware IOC extraction. The package directory is `StaticFeatureExtractor/`. The main extractor class inside it is named `StaticIOCExtractor`. The CLI help text also prints `StaticIOCExtractor` as the program name. Use `StaticFeatureExtractor` in imports and `python -m`.

The code parses files statically. It never executes a sample.

Three-layer pipeline complementing AutoPYara's hex-byte rule generation
with structured, nuanced static features.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Layer 1: EnsembleDetector + StaticFeatureModel                  │
│           EMBER-LightGBM + needforspeed + heuristic/token model  │
│           → P(malicious); gates Layers 2+3                       │
├──────────────────────────────────────────────────────────────────┤
│  Layer 2: AutoPYara         → hex-byte YARA strings              │
│  Layer 3: StaticIOCExtractor → structured features + conditions  │
│           → composed into a single YARA rule                     │
└──────────────────────────────────────────────────────────────────┘
```

Layer 3 extraction always runs first. Layers 2/rule composition execute if
the detector or static feature model flags malware-like evidence, or if the
caller passes `force=True` (e.g., user has independently confirmed malware).

## Supported formats

PE (Windows + .NET), ELF (Linux), Mach-O (macOS), scripts (PowerShell,
JavaScript, VBScript, Python, shell, batch), Office (OLE + OOXML + RTF),
PDF.

## Files

| File | Role |
|---|---|
| `__init__.py` | Public API (see below). |
| `__main__.py` | CLI entry (`python -m StaticFeatureExtractor`). |
| `extractor.py` | `StaticIOCExtractor` and `extract()`. Routes to a format extractor using Magika and libmagic. |
| `schema.py` | `StaticFeatures` and its typed sub-records. Provides `to_dict`, `to_json`, `to_iocs`, `to_yara_conditions`. |
| `common.py` | Hashing, entropy, byte statistics, string extraction, file typing. |
| `pe.py`, `elf.py`, `macho.py`, `script.py`, `office.py`, `pdf.py` | Per-format extractors. `pe.py` also covers .NET. |
| `detector.py` | Layer 1 detectors: `EnsembleDetector`, `EmberDetector`, `Ember2024Detector`, `NeedForSpeedDetector`, `HeuristicDetector`, `DetectionResult`. |
| `feature_model.py` | Explainable feature judges: `HeuristicFeatureModel`, `SklearnOneClassFeatureModel`, `LMFeatureModel`, `feature_tokens`, training helpers. |
| `ember_feature_model.py` | `EmberFeatureModel`: EMBER2024-backed detector and YARA condition selector. |
| `ember2024.py` | Lazy `thrember` helpers: download plans, dataset and model download, vectorization. |
| `feature_to_iocs.py` | Bridge to the prompt builder: `features_to_ioc_dicts`, `features_to_prompt_kwargs`. |
| `pipeline.py` | `IOCExtractionPipeline` and `PipelineResult`. |
| `models/` | Holds `EMBER2024_all.model`, a local copy of an EMBER2024 benchmark model (pass it to `--ember2024`). |
| `test_extractor.py` | Unit tests (see Tests). |
| `requirements.txt` | Optional parser and model dependencies. |

## Quick start

```python
from StaticFeatureExtractor import (
    StaticIOCExtractor,
    IOCExtractionPipeline,
    EnsembleDetector,
    HeuristicFeatureModel,
    feature_tokens,
)
from pathlib import Path

# Just the extractor (Layer 3)
features = StaticIOCExtractor("/path/to/sample.bin").extract()
print(features.to_json(indent=2))
iocs = features.to_iocs()                    # 21-type IOC list
yara_conds = features.to_yara_conditions()   # YARA condition fragments
tokens = feature_tokens(features)            # model/training tokens
assessment = HeuristicFeatureModel().assess(features)

# Full pipeline
detector = EnsembleDetector.default(
    ember_model_path=Path("ember_model_2018.txt"),     # optional
    nfs_model_path=Path("nfs_model.pkl"),              # optional
    threshold=0.5,
)
pipeline = IOCExtractionPipeline(detector=detector, use_floss=False)
result = pipeline.analyze("/path/to/sample.bin")
print(result.composed_rule)                  # final YARA rule
```

If no ML model paths are provided, EMBER and needforspeed abstain and only
the heuristic fallback contributes — useful for development/CI.

Layer 2 imports `autopyara` lazily (`from autopyara import AutoPYara`). If the package is missing, the pipeline appends `autopyara init: ...` to `PipelineResult.errors`, leaves `autopyara_rule` as `None`, and still composes a rule from the Layer 3 conditions. You can also pass your own `autopyara_factory`. The gate returns verdict `benign` (no Layer 2 or rule) when both the detector and the feature model call the sample benign and `force` is off.

## CLI

```bash
# Layer 3 only — structured feature dump
python -m StaticFeatureExtractor extract /path/to/sample.bin --out features.json

# Extract plus malware-likeness feature assessment
python -m StaticFeatureExtractor extract /path/to/sample.bin \
    --out features.json --assessment-out assessment.json

# Judge an existing features.json dump
python -m StaticFeatureExtractor judge features.json

# Full pipeline — gate + AutoPYara + Layer 3 + composed rule
python -m StaticFeatureExtractor analyze /path/to/sample.bin \
    --ember /path/to/ember_model_2018.txt \
    --ember2024 /path/to/ember2024.model \
    --nfs /path/to/nfs_model.pkl \
    --threshold 0.5 \
    --out report.json --rule-out rule.yar

# Skip Layer 1 gate (caller is sure the sample is malicious)
python -m StaticFeatureExtractor analyze /path/to/sample.bin --force --rule-out rule.yar

# Train a one-class static-feature model from malware features JSONL
python -m StaticFeatureExtractor train-feature-model malware_features.jsonl \
    --model-out model_store/static_feature_oneclass.joblib

# Use a trained model for judging/pipeline gating
python -m StaticFeatureExtractor judge features.json \
    --feature-model model_store/static_feature_oneclass.joblib
python -m StaticFeatureExtractor analyze /path/to/sample.bin \
    --feature-model model_store/static_feature_oneclass.joblib \
    --rule-out rule.yar

# EMBER2024 dataset/model helpers. Dry-run first; PE train is ~38.4 GB.
python -m StaticFeatureExtractor ember2024-download-dataset /data/ember2024 \
    --split train --file-type PE --dry-run
python -m StaticFeatureExtractor ember2024-download-dataset /data/ember2024 \
    --split challenge
python -m StaticFeatureExtractor ember2024-download-models /models/ember2024
python -m StaticFeatureExtractor ember2024-vectorize /data/ember2024 \
    --label-type label
```

### CLI flag reference

Global: `-v`, `--verbose`. Every subcommand takes its input as a positional argument.

| Subcommand | Positional | Flags (defaults) |
|---|---|---|
| `extract` | `path` | `--floss`, `--out`, `--iocs`, `--assessment-out`, `--feature-threshold` (0.45), `--feature-model` |
| `judge` | `features_json` | `--feature-threshold` (0.45), `--feature-model`, `--out` |
| `analyze` | `path` | `--ember`, `--ember2024`, `--nfs`, `--threshold` (0.5), `--feature-threshold` (0.45), `--feature-model`, `--force`, `--floss`, `--rule-name`, `--out`, `--rule-out` |
| `train-feature-model` | `jsonl` | `--model-out` (required), `--nu` (0.05), `--max-features` (50000), `--min-df` (1), `--max-iter` (2000) |
| `ember2024-download-dataset` | `download_dir` | `--split {all,train,test,challenge}` (`challenge`), `--file-type {all,PE,Win32,Win64,Dot_Net,APK,ELF,PDF}` (`PE`; ignored for `challenge`), `--dry-run` |
| `ember2024-download-models` | `download_dir` | `--dry-run` |
| `ember2024-vectorize` | `data_dir` | `--label-type {label,family,behavior,file_property,packer,exploit,group}` (`label`), `--class-min` (10) |

The training JSONL can be either raw `StaticFeatures` objects or envelopes:

```json
{"sha256":"...","label":"malware","family":"agenttesla","features":{...}}
```

The one-class model learns "similar to known malware static features". It is
not a final benign-vs-malware oracle; add benign/background samples later for
a supervised classifier.

## EMBER2024

EMBER2024 is useful in two different ways:

- Download the benchmark `.model` files and pass one to `analyze` with
  `--ember2024`. This adds a thrember/LightGBM detector to Layer 1.
- Download features/labels and vectorize them with `ember2024-vectorize` when
  training larger malware-vs-benign, family, behavior, packer, exploit, or
  group classifiers.

The CLI defaults to the 126 MB challenge split for safer first experiments.
Approximate published feature+label sizes:

```
Win32 train 23.7 GB   Win32 test 4.9 GB
Win64 train 12.9 GB   Win64 test 2.5 GB
.NET  train 1.8 GB    .NET  test 425 MB
APK   train 1.0 GB    APK   test 234 MB
PDF   train 197 MB    PDF   test 46 MB
ELF   train 100 MB    ELF   test 24 MB
challenge 126 MB
```

For our explainable YARA feature filter, keep using `train-feature-model` on
`StaticFeatures` JSONL. EMBER2024 is the stronger source for detection
models; `StaticFeatures` remains the stronger source for readable feature
selection.

## Public API

Everything below is exported from `StaticFeatureExtractor/__init__.py`. Signatures were checked against the code.

| Name | Signature or role |
|---|---|
| `StaticIOCExtractor` | `(path, *, use_floss=False, compute_byte_stats=True, max_resources=256)`. `.extract()` returns `StaticFeatures`. `.data` holds the file bytes. |
| `extract` | `(path, **kwargs) -> StaticFeatures`. One-shot wrapper. |
| `StaticFeatures` | Typed container. Methods: `to_dict()`, `to_json()`, `to_iocs()` (21 types), `to_yara_conditions()`. |
| `FileFormat` | Enum: `PE`, `ELF`, `MACHO`, `DOTNET`, `SCRIPT`, `OFFICE`, `PDF`, `UNKNOWN`. |
| `EnsembleDetector` | `(detectors: list[(Detector, weight)], threshold=0.5)`. `EnsembleDetector.default(ember_model_path=None, ember2024_model_path=None, nfs_model_path=None, threshold=0.5)` builds the standard stack. |
| `HeuristicFeatureModel` | `(*, threshold=0.45, max_selected=12)`. `.assess(features)` returns `FeatureAssessment`. |
| `SklearnOneClassFeatureModel` | Trained one-class model. Create it with `train_one_class_feature_model`. |
| `train_one_class_feature_model` | `(jsonl_path, model_out, *, nu=0.05, max_features=50000, min_df=1, max_iter=2000, random_state=7)`. |
| `LMFeatureModel` | `(assistant, base_model=None, *, max_queries=6, threshold=0.45, max_selected=12)`. |
| `EmberFeatureModel` | `(model_path, *, threshold=0.5, top_k=12, use_shap=True, file_type="PE")`. |
| `feature_tokens` | `(features) -> list[str]`. Domain tokens for models and training. |
| `assessment_from_features_json`, `static_features_from_dict`, `iter_static_features_jsonl` | Load saved feature dumps. |
| `features_to_ioc_dicts` | `(features, *, include_hashes=False, max_sections=8, max_strings=30)`. |
| `features_to_prompt_kwargs` | `(features, assessment=None, *, include_hashes=False, max_sections=8, max_strings=30, malware_context=None)`. |
| `IOCExtractionPipeline` | `(detector=None, *, autopyara_factory=None, autopyara_preset="AutoPYara", feature_model=None, use_floss=False)`. `.analyze(path, *, force=False, rule_name=None)` returns `PipelineResult`. |
| `PipelineResult` | Fields: `path`, `verdict` (`"benign"`, `"malicious"`, `"forced"`, or `"error"`), `detection`, `features`, `feature_assessment`, `autopyara_rule`, `autopyara_meta`, `composed_rule`, `errors`. |
| `download_ember2024_dataset`, `download_ember2024_models`, `ember2024_download_plan`, `vectorize_ember2024_dataset`, `read_ember2024_vectorized_features`, `Ember2024Plan` | EMBER2024 helpers. These need the optional `thrember` package. |

The schema sub-records (`HashFeatures`, `PEHeaderFeatures`, `ImportFeatures`, `DotNetFeatures`, `ScriptFeatures`, and others) are also exported.

## IOC schema

`StaticFeatures.to_iocs()` flattens to the 21-type schema used by the
NER pipeline:

```
MD5, SHA-1, SHA-256, SSDEEP, FILE, REGISTRY, MAGIC, MAGIKA, IP,
PE.TYPELIB, PE.RESOURCES, PE.SECTION, PE.SECTION.MD5, PE.SECTION.NAME,
PE.SECTION.SIZE, PE.SECTION.ENTROPY,
DOTNET.NAME, DOTNET.REVISION_NUMBER, DOTNET.ASSEMBLY_NAME,
DOTNET.VERSION, DOTNET.STREAM
```

## Dependencies

Core extraction uses the Python standard library and degrades gracefully
when specialist parsers are unavailable.

Optional rich parsers: `lief`, `python-magic`, `magika`, `pefile`, `dnfile`,
`pikepdf`, `oletools`, `olefile`.

Optional extras: `ssdeep` (SSDEEP fuzzy hash), `lightgbm` + `ember-malware`
(EMBER detector), `joblib` (needforspeed/model loading), `numpy` (ML detector
feature vectors), `scikit-learn` (trainable static feature model), `thrember`
(EMBER2024 helpers), `floss` (opt-in deobfuscated string extraction).

Install rich parser dependencies:
```bash
pip install -r StaticFeatureExtractor/requirements.txt
```

## Design notes

- **LIEF over pefile**: more robust on malformed PEs; handles ELF/Mach-O
  uniformly. `pefile` is still used for `imphash` (Mandiant reference
  implementation), `authentihash`, and Rich-header PV hash.
- **dnfile for .NET**: more complete than LIEF or pefile for managed
  binaries' metadata streams.
- **`parse_errors` field**: the extractor never raises on a malformed
  sample; failures are recorded and parsing continues with whatever
  subset is recoverable.
- **EMBER byte histograms**: included as-is for the ML detector.
  Computed once, used by both Layers 1 and 3.
- **EMBER2024**: optional thrember integration can download benchmark models,
  download/vectorize dataset chunks, and run a downloaded LightGBM `.model`
  as an additional detector.
- **Static feature model**: `feature_tokens()` turns structured features into
  a compact domain-token language. The default heuristic model is fully
  explainable; the optional scikit-learn one-class model can be trained from
  malware JSONL and used as a local, low-RAM feature filter.
- **No always-true conditions**: `to_yara_conditions()` deliberately
  omits `hash.sha256(0, filesize) == "..."`. That's a fingerprint, not
  a hunting condition; it lives in the meta block instead.
- **Suspicious-API list**: ~80 curated APIs covering injection, memory
  manipulation, hooking, network, anti-analysis, crypto, services, and
  shell execution. Used both as a feature for the heuristic detector
  and as IOC context for downstream rule synthesis.

## Tests

```bash
python -m unittest StaticFeatureExtractor.test_extractor   # run from the repo root
```

`test_extractor.py` has about 20 tests covering PE, ELF, scripts, PDF, Office, the
feature model, the pipeline, and robustness on corrupt or empty input. It builds
minimal synthetic samples and uses no real malware. As of this writing the file
fails at import: line 20 reads `from . import StaticFeatureExtractor`, which no
longer resolves after the package rename. Change it before relying on the tests.

# YaraGen.SampleClassifier

Classifiers for **binary samples**, used to discover rule-worthy features that a
string extractor would not find. The folder is named `SampleClassifier` so that it
does not clash with [`../Classifier`](../Classifier/README.md), which classifies
YARA rules. There are two models, and the point is to run both:

- **Model A** (`model_a.py`): string-presence LightGBM over the
  `StaticFeatures` cache. It runs on CPU and points at strings directly. It is
  also the baseline: if the byte model cannot beat it, byte-level discovery added
  nothing.
- **Model B** (`model.py`, `train.py`, `attribute.py`): a window-strided
  MalConv over raw bytes with two heads (malware vs goodware, and family).
  Attribution turns its evidence into `HEX_SPAN` candidates for ISB.

**Safety.** Sample bytes are read with `open(rb)` and are never executed.

## What is in this folder

| File | Role |
|---|---|
| `data.py` | `ClassifierDataspec` (splits and the leakage guard), `DataConfig`, `SampleRef`, `WindowSampler`, `read_windows`, `FAMILY_UNLABELED`, `KNOWN_SINGLETON_FAMILIES`. Imports no torch. |
| `dataset.py` | `WindowDataset`, `collate_windows`: torch dataset with per-epoch window resampling. |
| `model.py` | `WindowMalConv`, `ModelConfig`, `masked_family_loss`, `PAD_BYTE`. |
| `train.py` | `ClassifierTrainer`, `TrainConfig`, `variant_name`, `load_checkpoint`. DDP-aware (`torchrun`). |
| `model_a.py` | `StringPresenceClassifier`, `ModelAConfig`, `record_feature_values`. |
| `attribute.py` | `Attributor`, `AttributionConfig`, `AttributedSpan`: windows, integrated gradients, spans, stability gate. |
| `emit_spans.py` | `emit_family_spans`, `SpanEmitConfig`: the classifier's candidate source for ISB. Import by module path. |

The package exports the data classes eagerly and loads the torch and LightGBM
classes on first use. `import YaraGen.SampleClassifier` stays cheap.

## Public API

```python
from YaraGen.SampleClassifier import (ClassifierDataspec, DataConfig, SampleRef,
    WindowSampler, ModelConfig, WindowMalConv, ClassifierTrainer, TrainConfig,
    load_checkpoint, StringPresenceClassifier, Attributor, AttributionConfig)
from YaraGen.SampleClassifier.emit_spans import emit_family_spans
```

| Call | Purpose |
|---|---|
| `ClassifierDataspec(DataConfig(...))` | Build the train, binary-validation and family-validation lists. It asserts that no F_dev or F_test family and no evaluation goodware can reach training. Set `malware_split` and `goodware_split` (JSON), `corpus_root`, `manifest`; the vault arm also needs `vault_screen`. |
| `ClassifierTrainer(dataspec, config=None, out_dir="", sections_of=None).train()` | Train the byte model. `TrainConfig.from_env()` reads overrides such as `VAULT`, `WINDOW`, `N_WINDOWS`, `EPOCHS`, `BATCH_SIZE`. Writes `best.pt`, `best_auc.pt` and `last.pt` checkpoints and `report.json` to `out_dir`. |
| `load_checkpoint(path, device="cpu")` | `(model, blob)`. The blob holds `model_config`, `train_config`, `family_names`, `sampler`. |
| `WindowMalConv(ModelConfig(...))(windows, mask=None)` | `windows` is an integer tensor `(batch, n_windows, window_len)` with byte values 0-255 and padding 256. Returns a dict: `logit_binary (B,)`, `logits_family (B, n_families)`, `window_contribution (B, W)`, `window_embeddings`, `file_embedding`. |
| `StringPresenceClassifier(config=None)` | `fit(refs, get_record, family_names)`, `predict_binary`, `predict_family`, `malware_ranked_values`, `family_ranked_values`, `save(out_dir)`, `load(pkl_path)`. `get_record` maps a sha256 to a `StaticFeatures` record. |
| `Attributor(model, sampler, family_names, config=None, device="cpu")` | `candidates_for_family(family, gen_refs, sections_of=None, m=None)` returns `list[Candidate]` of type `HEX_SPAN`. |
| `emit_family_spans(attributor, family, gen_refs, config=None, progress=None)` | Per-sample candidates plus a presence map, ready for `FamilyCandidateSet.add_sample`. Returns a dict. |

`ModelConfig` defaults: `embed_dim=8, channels=128, kernel_size=512,
stride=512, n_families=23, pooling="attention", hidden=256, dropout=0.2,
family_loss_weight=0.5`. `WindowSampler` defaults: `window_size=262144,
n_windows=32, stratify="uniform"`.

`AttributionConfig` controls attribution: `top_k_windows=4`, `ig_steps=16`,
`min_span_bytes=8`, `max_span_bytes=64`, `stability_frac=0.2`,
`stability_floor=2`, `family_target="argmax"`.

## Example

```python
import torch
from YaraGen.SampleClassifier import WindowMalConv, ModelConfig

model = WindowMalConv(ModelConfig(n_families=5)).eval()
x = torch.randint(0, 256, (2, 3, 4096))          # 2 files, 3 windows, 4096 bytes
out = model(x)
out["logit_binary"].shape, out["logits_family"].shape   # (2,), (2, 5)
```

With a trained checkpoint, the byte-span path is:

```python
model, blob = load_checkpoint("<path/to/best.pt>")
att = Attributor(model, WindowSampler(**blob["sampler"]), blob["family_names"])
cands = att.candidates_for_family("<family>", gen_refs)   # HEX_SPAN candidates
```

## Inputs, outputs and data

- Inputs are a frozen split (malware and goodware JSON with a `samples` map of
  sha256 to path, PE flag, family, split and side), a corpus manifest CSV, and,
  for Model A, the `StaticFeatures` cache. The repo does not include the corpus;
  set `DataConfig` paths for your machine.
- Family labels cover `F_train` families only. Samples without a family label
  train the binary head, and the family loss ignores them.
- Output: checkpoints (`.pt`), a `report.json`, ranked string values, and
  `HEX_SPAN` candidates.

## Gotchas

- **Leakage rules are enforced in code.** Attribution runs on a family's `gen`
  samples with frozen weights from a model that never saw that family. Never pass
  `held` samples to `Attributor`.
- `DataConfig` defaults for `corpus_root`, `manifest` and `collisions` point at
  machine-specific locations. Always set them.
- `vault=True` requires `vault_screen`, unless you set
  `allow_unscreened_vault=True` to measure the leak.
- `family_target="true"` is for analysis on training families only.
- Checkpoint selection defaults to `"combined"` (binary AUC plus family top-1),
  because the two heads peak at different epochs.
- Hex spans still need the goodware span index before they are trusted (see
  `YaraGen/StaticFeatures/spanindex.py`).

## Related

- [`../StaticFeatures/README.md`](../StaticFeatures/README.md) for the cache.
- [`../ISB/README.md`](../ISB/README.md) consumes the candidates.
- [`../Classifier/README.md`](../Classifier/README.md) for rule classification.
- [`../../StaticFeatureExtractor/README.md`](../../StaticFeatureExtractor/README.md)
  for another static detector.

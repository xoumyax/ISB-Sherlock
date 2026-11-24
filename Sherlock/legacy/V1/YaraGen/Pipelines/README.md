# YaraGen.Pipelines

Facades that run a whole pipeline behind one call. The package holds one class, `BinaryToRule`, which runs the Exp 2 chain from malware samples to a YARA rule. It replaces the former `RuleGeneratorIOC` stub, which imported a `YaraGen.Models` module that does not exist in this repository.

## What is in this folder

| File | Role |
|---|---|
| `__init__.py` | Exports `BinaryToRule` and `BinaryToRuleConfig`. |
| `BinaryToRule.py` | The implementation. |

## Stages

`BinaryToRule.generate(paths)` runs these steps:

1. Static extraction per sample: [`StaticFeatures`](../StaticFeatures/README.md) (`extract_record`, `record_to_candidates`).
2. Optional attributed byte spans from a trained sample classifier: [`SampleClassifier`](../SampleClassifier/README.md).
3. Family pooling of candidates: [`ISB`](../ISB/README.md) (`FamilyCandidateSet.pool`).
4. Expressibility filter, stoplist and goodware-genericity drop.
5. Ranking by the trained salience scorer, or by `PriorScorer` when none is configured.
6. Budget (`apply_budget`) and condition plan (`ConditionBrain.plan`).
7. Rendering with the deterministic template renderer in [`RuleSynth`](../RuleSynth/README.md). No language model is involved.

## Public API

```python
from YaraGen.Pipelines import BinaryToRule, BinaryToRuleConfig
```

`BinaryToRuleConfig(df_index_path=None, span_index_path=None, salience_dir=None, classifier_path=None, budget=BudgetConfig(), condition=ConditionConfig(), strict=True, device="cpu")`

| Field | Meaning |
|---|---|
| `df_index_path` | Goodware document-frequency index for strings (built by `StaticFeatures/dfindex.py`). |
| `span_index_path` | Goodware byte-substring presence index. Needed to score hex-span candidates. |
| `salience_dir` | Directory with a trained scorer (`salience.txt`, optional `salience.meta.json`). Falls back to `PriorScorer` if absent. Needs `lightgbm`. |
| `classifier_path` | Byte-CNN checkpoint. Adds attributed `HEX_SPAN` candidates. Without it the run is static-only. |
| `budget`, `condition` | `ISB.budget.BudgetConfig` and `ISB.condition.ConditionConfig`. |
| `strict` | When True, raise `RuntimeError` if no goodware index loaded. |
| `device` | Device for the classifier. |

`BinaryToRule(config=None)` loads the goodware oracle, stoplist, condition planner and scorer. Methods:

- `generate(sample_paths, family_hint=None, arm="learned") -> dict`
- `candidates(paths) -> FamilyCandidateSet`: stages 1-2 only.

`generate` returns a dict with these keys: `rule` (rule text), `family`, `n_samples`, `n_candidates`, `n_after_hygiene`, `selected`, `condition`, `dropped`, `budget`, `goodware_verified`, `goodware_indexes`, `scorer`, `is_dead`. `family_hint` becomes the family name in the rule (default `"unknown_family"`).

## Usage

```python
from YaraGen.Pipelines import BinaryToRule, BinaryToRuleConfig

cfg = BinaryToRuleConfig(
    df_index_path="<path/to/goodware_df_index>",
    span_index_path="<path/to/goodware_span_index>",
)
b2r = BinaryToRule(cfg)
out = b2r.generate(["<path/to/sample1>", "<path/to/sample2>"], family_hint="examplefamily")
print(out["rule"])
print(out["goodware_verified"], out["dropped"])
```

## Inputs and outputs

- **Inputs.** Paths to sample files, and the index and checkpoint paths in the config. Samples are read as bytes (`open(rb)`, `pefile`) and never executed.
- **Output.** A dict. `out["rule"]` is YARA source text.

## Gotchas

- **Goodware indexes decide quality.** Hygiene decisions ask whether a value occurs in benign software. With no index every candidate looks clean and the rule can match goodware. `strict=True` (default) refuses to run without one. With `strict=False` the rule carries `goodware_verified = "false"` in its metadata.
- **`arm` is a label.** In `generate`, `arm` is written into the rule's metadata and name. The selection steps above do not change with it.
- **Live malware.** The corpora are live malware. Use static analysis only.
- **Optional stages load lazily.** The classifier and LightGBM load only if you configure them.

## Related

[`Bazaar`](../Bazaar/README.md) collects the samples. [`Detection`](../Detection/README.md) scores the resulting rules. [`Inference`](../Inference/README.md) is the text-prompt path to a rule.

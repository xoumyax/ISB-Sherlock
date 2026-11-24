# YaraGen.RuleSynth

Turns an ISB selection into a compilable YARA rule. There are two writers. The
**template** writer is deterministic and needs no model: it renders the
condition plan exactly. The **LM** writer prompts one of the trained YaraGen
generators with the same plan and returns the rule the model writes. Both start
from the same selection, so differences between them come from the writer, not
from the indicators.

## What is in this folder

| File | Role |
|---|---|
| `template.py` | `render_template_rule`, `RenderedRule`, `YARA_MAX_STRINGS`. The no-LM writer. |
| `llm.py` | `LMRuleGenerator`, the `MODELS` registry, prompt builders (`build_prompt`, `plan_prompt`, `describer_prompt`) and `RQ9_SYSTEM_PROMPT`. |
| `__init__.py` | Exports the names above. It loads `llm.py` lazily, so `from YaraGen.RuleSynth import render_template_rule` does not import torch. |

## Public API

```python
from YaraGen.RuleSynth import render_template_rule, RenderedRule   # CPU only
from YaraGen.RuleSynth import LMRuleGenerator, MODELS               # loads llm.py
```

```python
render_template_rule(family, selected, arm="template", brain=None, plan=None,
                     config=DEFAULT_CONFIG, rule_name=None) -> RenderedRule
LMRuleGenerator(model, device="cuda", verbose=False, chunk_size=0,
                prompt_style="describer")
LMRuleGenerator.generate(plan, arm="learned", rule_name=None,
                         template_source=None) -> RenderedRule
```

`render_template_rule` filters `selected` through the ISB grammar, builds a
`ConditionPlan` with `ConditionBrain` (or uses the one you pass), and writes the
rule. Strong strings get `$s0...` identifiers and weak strings get `$w0...`. The
rule has a `meta:` block with `family`, `arm` and `generator`. An empty plan
renders `condition: false`.

`RenderedRule` fields:

| Field | Meaning |
|---|---|
| `name`, `source`, `family`, `arm` | Rule name, rule text, and provenance. |
| `n_strong`, `n_weak`, `n_module_terms`, `n_of` | Shape of the condition. |
| `n_strings`, `over_string_limit` | String count, and whether it exceeds `YARA_MAX_STRINGS` (10,000). |
| `dropped` | Counts of candidates dropped by the grammar, or error markers from the LM path. |
| `is_dead` | `True` for a `false` condition, or when the LM emitted no rule. |

`summary()` returns the same fields as a plain dict.

### LM generators

`MODELS` is a registry keyed by name. The keys are `bart`, `bart_scooper`,
`bart_humanized`, `bart_taskmix_base`, `bart_taskmix_human`,
`t5gemma_humanized`, `codet5p_consistency`, `llama1b_consistency_step25934`,
`lfm2_consistency`, `ministral` and `llama_taskmix`. Each entry sets the
checkpoint path, `kind` (`seq2seq` or `causal`), the YaraAST token file,
`use_slot_canonicalization`, an optional `prompt_prefix` (for example
`"<task:generation> "`), and for `bart_scooper` the IOC scooper paths. The
checkpoints live outside the repo, and the paths are written in `llm.py`. Edit
the `MODELS` entries to point at your copies.

`generate` never raises for a model failure. It returns a `RenderedRule` with
`is_dead=True` and the reason in `dropped`. A fatal CUDA error is the exception:
it raises `RuntimeError`, because every later call would fail the same way.

`prompt_style` chooses the prompt:

| Style | Prompt |
|---|---|
| `"describer"` | `RuleDescriber` English for the template rule (pass it as `template_source`). Matches the training distribution. |
| `"planformat"` | The same wording built straight from the plan, without a template rule. |
| `"handbuilt"` | `build_prompt(plan)`: a hand-written instruction. The module docstring reports that models copy its labels into the rule. Kept for comparison. |

`chunk_size > 0` generates one rule per chunk of candidates and joins them with
`RuleMerger.merge_rules_threshold`. This is the path for small models on CPU.

## Example

```python
from YaraGen.ISB import ConditionBrain, GoodwareOracle
from YaraGen.RuleSynth import render_template_rule, LMRuleGenerator

# `selected` is a list of Candidate objects from ISB.run_arm(...).selected
tpl = render_template_rule("demo", selected, arm="learned")
print(tpl.source)

plan = ConditionBrain(GoodwareOracle()).plan("demo", selected)
gen = LMRuleGenerator("bart", device="cuda")
lm = gen.generate(plan, arm="learned", template_source=tpl.source)
lm.is_dead, lm.source
```

## Inputs, outputs and data

- Input: a list of `Candidate` objects (template) or a `ConditionPlan` (LM).
- Output: `RenderedRule`. Feed `source` to
  [`../Detection/README.md`](../Detection/README.md).
- The LM path needs a GPU, a checkpoint from `MODELS`, and the
  `YaraGen.Inference.RuleGenerator` class. It caps the input length at the
  model's position-embedding limit (1024 for BART).
- The scooper entries resolve their relative paths against the repo root, for
  example `YaraGen/IOCExtractor/Models/YARA_IOCScooper_V6.0_full.pt`.

## Gotchas

- With `prompt_style="describer"` and no `template_source`, the code falls back
  to the hand-built prompt without a warning. Always pass `template_source`.
- Do not change how prompts are decorated for a checkpoint. The `TaskMix` and
  Llama models need the `<task:generation> ` prefix and the system prompt in
  `RQ9_SYSTEM_PROMPT`.
- Unbudgeted selections (`all`, `lint`) can exceed 10,000 strings. The rule is
  rendered, but libyara will not compile it.
- `render_template_rule` raises if a candidate gets past the grammar filter and
  cannot be rendered. It does not write a rule that fails at scan time.

## Related

- Tests: `tests/test_detection.py` covers template rendering.
- [`../ISB/README.md`](../ISB/README.md) for selections and plans.
- [`../Describer/README.md`](../Describer/README.md), [`../Merger/README.md`](../Merger/README.md).
- [`../IOCExtractor/README.md`](../IOCExtractor/README.md) for the scooper.
- [`../../ReportScooper/README.md`](../../ReportScooper/README.md).

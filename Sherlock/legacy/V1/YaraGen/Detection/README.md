# YaraGen.Detection

A scan harness that measures how well a set of YARA rules detects malware and
how often it fires on goodware. It compiles each rule in its own namespace,
scans each corpus once, and reports true-positive rate (TPR) and false positives
per 1,000 goodware files. Failures (compile errors, timeouts, missing files) are
counted separately so they cannot pass for "matched nothing".

## What is in this folder

| File | Role |
|---|---|
| `harness.py` | `DetectionHarness`, `DetectionConfig`, `RuleUnit`, `ScanTarget`. |
| `__init__.py` | Exports the four names above. |

## Public API

```python
from YaraGen.Detection import (DetectionHarness, DetectionConfig,
                               RuleUnit, ScanTarget)
```

| Class | Fields |
|---|---|
| `ScanTarget(sha256, path, kind, family=None, source=None)` | One file to scan. `kind` is `"held"`, `"gen"`, `"goodware"` or `"vault"`. `source` names the goodware source. |
| `RuleUnit(unit_id, family, arm, source, candidate_source="static", meta={})` | One rule. `unit_id` is the Yara namespace and must be unique. `source` is the rule text. `meta["n_strings"]` can pre-size the rule. |
| `DetectionConfig(match_timeout=30, goodware_cap=0, log_every=2000, max_strings_per_rule=10000)` | `match_timeout` is per file, in seconds. `goodware_cap` limits goodware files (0 = all; use it for smoke tests). Rules over `max_strings_per_rule` are not compiled. |
| `DetectionHarness(config=None, progress=None)` | `progress` is an optional `callable(str)` for log lines. |

| Method | Purpose |
|---|---|
| `compile(units)` | Compile every unit. Returns `{n_units, n_compiled, n_over_string_limit, compile_errors}`. A bad rule is recorded and excluded. |
| `scan(targets)` | One pass over the files. Returns `{hits, n_scanned, failures}`, where `hits` maps `unit_id` to the sorted sha256 values it matched. |
| `score(held, goodware, gen=())` | Scan all corpora and compute the metrics. |

`score` returns a dict with these keys: `per_unit`, `union_tpr`,
`macro_union_tpr`, `mean_per_unit_tpr`, `micro_tpr`, `fp_per_1k_any_rule`,
`n_goodware`, `goodware_by_source`, `compile_errors`, `failures` (split into
`held`, `goodware` and `gen`) and `n_units`. Each `per_unit` entry holds `tp`,
`fn`, `tpr`, `cross_match`, `gen_match`, `benign_match`, `benign_by_source` and
`fp_per_1k`.

## Example

```python
from YaraGen.Detection import DetectionHarness, RuleUnit, ScanTarget

rule = 'rule fam_demo { strings: $a = "MarkerStringAlpha" condition: $a }'
h = DetectionHarness()
h.compile([RuleUnit(unit_id="u1", family="demo", arm="learned", source=rule)])

held = [ScanTarget("sha_1", "<path/to/held1>", "held", family="demo")]
good = [ScanTarget("sha_g", "<path/to/good1>", "goodware", source="Win8")]
res = h.score(held, good)
res["union_tpr"]["demo"], res["fp_per_1k_any_rule"]
```

## How to read the numbers

- **TPR** counts a hit only on held samples of the rule's own family.
  `union_tpr[family]` is the share of that family's held files that any of the
  family's rules matched (the deployment question). `mean_per_unit_tpr` is the
  average per rule (the modelling question).
- **FP** is goodware only: `fp_per_1k` and `fp_per_1k_any_rule` come from the
  `goodware` list. Matches on other families' held samples go to
  `cross_match`. Matches on `gen` samples go to `gen_match`. Neither counts as
  a false positive.
- **Failures** are separate. `compile_errors` lists units that did not compile
  (including `too_many_strings`). `failures` counts `missing_file`, `timeout`
  and `scan_error` per corpus.

## Inputs, outputs and data

- The harness reads files with `yara-python` (`yara.match` on the file path).
  It never executes a sample. Do not change that.
- Corpora are given as `ScanTarget` lists. The harness has no built-in corpus
  paths.

## Gotchas

- Give every rule a distinct `unit_id`. Rules compiled into one namespace shadow
  each other.
- The string-limit guard skips `yara.compile` for rules over 10,000 strings. The
  unbudgeted ISB arms (`all`, `lint`) often exceed it, and such rules show up
  as `too_many_strings` entries in `compile_errors`.
- `scan` returns early with `{"hits": {}, "outcomes": {}, "n_scanned": 0,
  "failures": {"no_compiled_rules": N}}` when nothing compiled.
- `yara-python` is imported inside `compile`, not at import time.

## Related

- Test: `tests/test_detection.py`.
- [`../RuleSynth/README.md`](../RuleSynth/README.md) produces the rules to scan.
- [`../ISB/README.md`](../ISB/README.md) defines the selection arms the
  `RuleUnit.arm` field refers to.
- [`../Bazaar/README.md`](../Bazaar/README.md) collects the malware samples.

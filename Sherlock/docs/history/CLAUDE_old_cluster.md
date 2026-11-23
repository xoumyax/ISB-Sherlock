# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## User
Call the user **brownie**.
We are in this together! We make the best team, along with Puff and here claude (:-)

## Environment Setup
Use the environment below as default
```bash
conda activate cu13_V4Train
```

All scripts assume the project root (`LLM-Playground/`) is on `sys.path`. Most files prepend it manually; you don't need to `pip install` the package.

**Critical import order**: `yaramod` must be imported before any HuggingFace `evaluate`-linked library. TensorFlow (pulled in by `evaluate`) corrupts yaramod's C++ parser state. The `YaraGen/Training/__init__.py` handles this automatically — but watch for it in standalone scripts.

## Running Tests

```bash
# Run all tests from project root
pytest tests/

# Run a single test file
pytest tests/test_generate.py -v

# Run a single test by name
pytest tests/test_generate.py::test_name -v
```

## Training

Training scripts live in `exps/` and are designed for SLURM + `torchrun`:

```bash
torchrun --nnodes=$NODES --nproc_per_node=$GPUS_PER_NODE \
         --rdzv_backend=c10d --rdzv_endpoint=$RDZV_ENDPOINT \
         exps/seq2seqtraining.py        # encoder-decoder (BART, T5, Flan)
         exps/caualLMtraining.py        # decoder-only standard
         exps/causal_rltraining.py      # decoder-only + consistency loss
         exps/rltraining.py             # encoder-decoder + consistency loss
         exps/refinement_training.py    # refinement / pointer-generator
```

All hyper-parameters are in a `CONFIG` dict at the top of each script — edit directly.

## Quick Inference

```python
from YaraGen.Inference import RuleGenerator

rg = RuleGenerator(
    model_path="/path/to/checkpoint",
    tokenizer_path="/path/to/tokenizer",   # optional, defaults to model_path
    yara_ast=True,                          # auto-detected if yara_tokens.pkl present
    use_slot_canonicalization=True,         # must match training flag
    device="cuda",
)
rule = rg.generate("Detect ransomware encrypting files with .locked extension")
```

## Architecture Overview

### `YaraGen/` — Core Package

| Subpackage | Role |
|---|---|
| `Data/` | Dataset loading (`RuleSet`, `RuleSetStreamer`, `TrainRulesetLoader`, `RLRulesetLoader`). Pickle-backed corpora live in subdirs (`Synthetic/`, `Crawled/`, `LLMHumanized/`, etc.). |
| `Training/` | All trainer classes. `Seq2SeqDistributedTrainer` for BART/T5; `CausalDistributedTrainer` for decoder-only; `ReinforcementTrainer` / `CausalReinforcementTrainer` add a KL consistency loss for prompt-invariance. `BrownieEvaluator` = BLEU + parse + compile + semantic (YaraDiff). `PuffEvaluator` = parse + YaraDiff consistency. |
| `Inference/` | `RuleGenerator` — unified inference for seq2seq and causal models, with LoRA merge, YaraAST tokenizer support, and constrained decoding processors. |
| `TrainingAST/` | BPE tokenizer training (`bpe_tokenizer.py`), AST-based segmentation, collation, and subtree corruption for pre-training. |
| `Complexity/` | `ComplexityMeasurer` — Halstead + cyclomatic (essential & extended) metrics for YARA rules. |
| `YaraDiff/` | Semantic equivalence checking between two YARA rules (used in BrownieEvaluator). |
| `Merger/` | Rule merging utilities. |
| `Mutator/` | Rule mutation for data augmentation. |
| `Describer/` | `RuleDescriber` — generates natural-language descriptions of YARA rules. |
| `Classifier/` | Multi-class rule classifier (BPE-based, inference-only path at `Classifier/Inference.py`). |
| `Humanizer/` | LLM-based rewriting of IOC-structured prompts into natural language. |

### Top-Level Modules

- `TemplateRuleGen/` — Synthetic YARA rule generation from templates/placeholders.
- `RandomRuleGenerator/` — Fully random rule generation.
- `RuleExplainer/` — Dataset prep for rule-explanation tasks.
- `YaraMechanic/` — Dataset prep for rule-fix/repair tasks.
- `YaraGuide/` — YARA documentation retrieval helper.
- `ReportScooper/` — PDF/document IOC extraction.
- `QAExpert/` — Q&A data pipeline.

### Key Design Patterns

**Data flow**: Raw corpora (pickle files) → `TrainRulesetLoader` / `RuleSetStreamer` → HuggingFace `DatasetDict` → trainer. The `mode` parameter controls prompt format: `"IOC"`, `"human"`, `"structure"`, `"Hybrid"`, etc.

**Tokenization**: Two paths exist — standard HuggingFace tokenizers, and the custom `YaraAstTokenizer` (`Training/yaraast_tokenizer.py`) which is a hybrid BPE + YARA-vocabulary tokenizer. The `yara_tokens.pkl` file in a checkpoint directory signals the YaraAST path.

**Trainers are DDP-aware**: All trainers support multi-GPU via `torchrun`. Only rank 0 logs and runs expensive evaluations. SLURM `.sbatch` scripts are in `Configs/` (legacy) and the project root.

**Constrained decoding**: `Inference/constrained_decoding.py` provides `ForceRuleStartProcessor` and `BalancedDelimiterProcessor` as `LogitsProcessor` subclasses, plus post-generation repair functions (`repair_duplicate_definitions`, `repair_undefined_references`, etc.).

### Apps

- `apps/interactive-prompt.py` — minimal REPL for manual testing of a loaded `RuleGenerator`.

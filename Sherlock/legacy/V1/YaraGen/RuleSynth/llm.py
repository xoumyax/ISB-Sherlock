"""LM rule generation: an ISB-B condition plan -> a YARA rule, via our models.

The ``template`` renderer (:mod:`template`) is the control -- it makes the arm
ladder readable by removing generation variance. This module is the actual
deliverable: the trained YaraGen generators writing the rule.

Model configuration is **lifted from the proven RQ4 end-to-end config**
(``ReportScooper/experiments/rq4_e2e.py``) rather than re-derived, because the
failure mode here is silent. These checkpoints were trained with specific
prompt decorations -- the TaskMix Llama needs the literal ``<task:generation> ``
prefix its training metadata used, and both 8Bs need the RQ9 system prompt
verbatim. Get either wrong and the model still emits *something*, plausible and
worse, with nothing raising.

**Prompts come from RuleDescriber, over the template rule.** This is a
deviation from EXP1_DESIGN §6 ("No RuleDescriber. Prompts are built directly by
the experiment") and needs brownie's ruling -- but it is not a preference, it is
what the checkpoints were trained on, and the difference is not subtle.

Measured 2026-08-21, BART, same selection, same k=8 candidates:

* Hand-built prompt (``build_prompt``, EXP1 §6 style): the model copied the
  prompt's own type labels into the rule body -- ``$sz10 = "2_SECTION
  '.data\x00Ic/`` -- emitted unterminated strings, and produced
  ``$sz2 and no of ( $sz9 )``, which is not YARA.
* Describer prompt: a clean compilable rule reproducing the ISB-B condition
  exactly, ``any of ( $sz0..$sz4 ) or 2 of ( $sz5, $sz6, $sz7 )``, all eight
  candidates preserved with correct modifiers.

The reason is distributional: these checkpoints were trained on the crawled
corpus's ``translation.en`` field, which RuleDescriber produces. A hand-written
instruction is out-of-distribution, and measuring a model on it would report
prompt mismatch as model incapability. ``build_prompt`` is kept so the
comparison can be reported as a prompt-sensitivity result rather than deleted.

The pipeline is therefore: ISB selection -> template rule -> RuleDescriber ->
prompt -> generator -> rule. Template and LM rules come from the same selection
and the same condition plan, which is what keeps the arms comparable.

Single-rule-first: one rule from the whole selection, gated on parse validity.
At k=8 there is no chunking pressure (the pre-wipe merge fallback existed for
selections an order of magnitude larger), so a failure here is a real failure
and is recorded as one rather than papered over by a merge.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..ISB.candidate import Candidate
from ..ISB.condition import ConditionBrain, ConditionPlan
from ..ISB.grammar import sanitize_rule_name
from .template import RenderedRule

__all__ = ["MODELS", "RQ9_SYSTEM_PROMPT", "build_prompt", "describer_prompt",
           "plan_prompt", "LMRuleGenerator"]

#: Verbatim from RQ9 / rq4_e2e. Do not paraphrase -- it is training-matched.
RQ9_SYSTEM_PROMPT = (
    "You are an expert cybersecurity analyst specializing in YARA rules. "
    "Given a natural language description of rule or malware behavior or "
    "indicators of compromise, generate the corresponding YARA rule."
    "Only generate the YARA rule without any additional commentary or "
    "explanation."
)

#: Model checkpoints root, from the environment (no absolute path in the repo;
#: brownie, 23 Nov 2026). Unset means the paths below are relative and unresolved.
_MODELS = os.environ.get("ISB_V1_MODELS", "")
_RQ7 = os.path.join(_MODELS, "RQ7-task-generalization")
_BART = f"{_RQ7}/GenerationBART-Final/checkpoint_final"
_TASKMIX = os.path.join(_MODELS, "RQ9-models-comparison", "TaskMix")
_RQ9_GEN = os.path.join(_MODELS, "RQ9-models-comparison", "Generation")
_RQ8 = os.path.join(_MODELS, "RQ8-Final")

#: Mirrors rq4_e2e.CONFIG["models"], minus the scooper stage -- Exp 2 feeds the
#: generator an ISB selection, not a report, so there is nothing to re-extract.
MODELS: dict[str, dict[str, Any]] = {
    "bart": {
        "kind": "seq2seq",
        "model_path": _BART,
        # checkpoint_final is flat: weights + tokenizer + yara_tokens.pkl.
        "yara_tokens_path": f"{_BART}/yara_tokens.pkl",
        "use_slot_canonicalization": True,      # RQ7/RQ8 lineage flag
        "max_new_tokens": 1024,
    },
    # Same checkpoint as `bart`, run under Scooper-ALL. A separate key rather
    # than a flag on `bart`, so both configurations can sit in one results
    # table and neither silently redefines the other.
    #
    # The scooper replaces each IOC with a placeholder before the model sees
    # it and restores the exact bytes afterwards, so the literal indicator
    # cannot be garbled -- the model is only asked for structure. This is the
    # edge-deployment path: a 139M seq2seq on CPU reaching usable fidelity
    # without an 8B generator. Paths and seq-len follow rq4_e2e (BART uses the
    # BiLSTM V6 scooper; 1024 is the V6.0 convention).
    "bart_scooper": {
        "kind": "seq2seq",
        "model_path": _BART,
        "yara_tokens_path": f"{_BART}/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "scooper": True,
        "scooper_path": "YaraGen/IOCExtractor/Models/YARA_IOCScooper_V6.0_full.pt",
        "scooper_tokenizer_path": "YaraGen/IOCExtractor/Tokenizers/yaraIOCtokenizer_UNI.model",
        "scooper_sequence_length": 1024,
        "max_new_tokens": 1024,
    },

    # --- the other three RQ7 BARTs -------------------------------------
    # All four are YaraAST (yara_tokens.pkl) and all run
    # use_slot_canonicalization=True, per finalExperimets/RQ7-Final and
    # performance-across-tasks/perf_eval_common.py. What differs is the PROMPT
    # REGISTER they were trained on, which is exactly what we are picking
    # between: structured vs humanized, untagged vs task-tagged.
    #
    # `version` in measure_accuracy_rq7final.py is the authority:
    #   basic   = untagged prompts
    #   taskmix = "<task:generation> " prefixed (TAG_GEN, stage3_train_taskgen)
    "bart_humanized": {
        # Warm-started from GenerationBART-Final, then trained on humanized
        # (natural-language) prompts -- the one built for noisier input.
        "kind": "seq2seq",
        "model_path": f"{_RQ7}/HumanizedBART-Final/best_checkpoint",
        "yara_tokens_path": f"{_RQ7}/HumanizedBART-Final/best_checkpoint/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "max_new_tokens": 1024,
    },
    "bart_taskmix_base": {
        # Structured generation + patching, tagged.
        "kind": "seq2seq",
        "model_path": f"{_RQ7}/RQ7-YaraGen-TaskMix-Base/best_checkpoint",
        "yara_tokens_path": f"{_RQ7}/RQ7-YaraGen-TaskMix-Base/best_checkpoint/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "prompt_prefix": "<task:generation> ",
        "max_new_tokens": 1024,
    },
    "bart_taskmix_human": {
        # Humanized generation + patching, tagged.
        "kind": "seq2seq",
        "model_path": f"{_RQ7}/RQ7-YaraGen-TaskMix/best_checkpoint",
        "yara_tokens_path": f"{_RQ7}/RQ7-YaraGen-TaskMix/best_checkpoint/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "prompt_prefix": "<task:generation> ",
        "max_new_tokens": 1024,
    },
    # --- RQ8-Final: the small/YaraAST architectures -----------------------
    # Contract from finalExperimets/RQ8-Final/evaluate_rq8final.py:
    #   is_ast   = yara_tokens.pkl exists  -> yara_ast + use_slot_canonicalization
    #   dtype    = float16 for seq2seq, bfloat16 for causal
    #   system   = None for seq2seq, SYSTEM_PROMPT for causal (byte-identical
    #              to RQ9_SYSTEM_PROMPT, so the one constant serves both)
    # No task tags anywhere in the RQ8 lineage.
    "t5gemma_humanized": {
        "kind": "seq2seq",
        "model_path": f"{_RQ8}/RQ8F-t5gemma-2-270m-270m-YaraAST/ep3-Humanized/best_checkpoint",
        "yara_tokens_path": f"{_RQ8}/RQ8F-t5gemma-2-270m-270m-YaraAST/ep3-Humanized/best_checkpoint/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        # NO torch_dtype: this checkpoint is MIXED-dtype on disk -- 674 bf16
        # params (body) and 237 fp32 (multi_modal_projector, decoder norms). A
        # plain transformers load reproduces the same split, so it is the
        # checkpoint, not our loader. Left mixed, the forward dies with
        # "expected mat1 and mat2 to have the same dtype: BFloat16 != float".
        # `cast_dtype` below unifies it after load.
        "cast_dtype": "float32",
        "max_new_tokens": 1024,
    },
    "codet5p_consistency": {
        "kind": "seq2seq",
        "model_path": f"{_RQ8}/RQ8F-codet5p-220m-YaraAST/ep4-Consistency/final_checkpoint",
        "yara_tokens_path": f"{_RQ8}/RQ8F-codet5p-220m-YaraAST/ep4-Consistency/final_checkpoint/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "torch_dtype": "float16",
        "max_new_tokens": 1024,
    },
    # PARTIAL ep4 (0.509 epochs), per the snapshot's own PROVENANCE.txt -- NOT
    # the finished consistency-RL model. The step number stays in the key so a
    # results table can never present it as the final ep4 cell.
    "llama1b_consistency_step25934": {
        "kind": "causal",
        "model_path": f"{_RQ8}/RQ8F-Llama-3.2-1B-Instruct-YaraAST/ep4-Consistency/eval_snapshot_step25934",
        "yara_tokens_path": f"{_RQ8}/RQ8F-Llama-3.2-1B-Instruct-YaraAST/ep4-Consistency/eval_snapshot_step25934/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "system_prompt": RQ9_SYSTEM_PROMPT,
        "torch_dtype": "bfloat16",
        "max_new_tokens": 1024,
        "partial_checkpoint": "ep4 @ 0.509 epochs (checkpoint-25934)",
    },
    "lfm2_consistency": {
        "kind": "causal",
        "model_path": f"{_RQ8}/RQ8F-LFM2.5-1.2B-Instruct-YaraAST/ep4-Consistency/final_checkpoint",
        "yara_tokens_path": f"{_RQ8}/RQ8F-LFM2.5-1.2B-Instruct-YaraAST/ep4-Consistency/final_checkpoint/yara_tokens.pkl",
        "use_slot_canonicalization": True,
        "system_prompt": RQ9_SYSTEM_PROMPT,
        "torch_dtype": "bfloat16",
        "max_new_tokens": 1024,
    },
    "ministral": {
        "kind": "causal",
        # A *Generation* checkpoint, not TaskMix: it was trained without task
        # tags, so it gets NO prompt_prefix. Adding one would put a token the
        # model never saw at the head of every prompt.
        "model_path": f"{_RQ9_GEN}/RQ9-Ministral-3-8B-Instruct-2512-Text-Generation-BaseTok/best_checkpoint",
        "torch_dtype": "bfloat16",
        "system_prompt": RQ9_SYSTEM_PROMPT,
        "yara_ast": False,                      # BaseTok checkpoint
        "use_slot_canonicalization": False,
        "max_new_tokens": 1024,
    },
    "llama_taskmix": {
        "kind": "causal",
        "model_path": f"{_TASKMIX}/RQ9-Llama-3.1-8B-Instruct-TaskMix-BaseTok/best_checkpoint",
        "torch_dtype": "bfloat16",
        "system_prompt": RQ9_SYSTEM_PROMPT,
        # TaskMix prefixed every generation prompt with this tag during
        # training (metadata task_tags); inference MUST match.
        "prompt_prefix": "<task:generation> ",
        "yara_ast": False,                      # BaseTok checkpoint
        "use_slot_canonicalization": False,
        "max_new_tokens": 1024,
    },
}


def _describe(cand: Candidate) -> str:
    return f"{cand.ctype} {cand.value!r}"


def build_prompt(plan: ConditionPlan, n_of: int | None = None) -> str:
    """Natural-language request stating the ISB-B condition shape (§8).

    Deliberately spells the condition out. The selection is the experimental
    variable; letting each model invent its own combining logic would fold
    generation choices into a selection result.
    """
    n_of = plan.n_of if n_of is None else n_of
    lines = [
        f"Write a YARA rule that detects the malware family {plan.family}.",
        "",
        "Use exactly these indicators and no others:",
    ]
    if plan.module_terms:
        lines.append("File-hash / imphash terms (any one identifies the sample):")
        lines += [f"  - {_describe(c)}" for c in plan.module_terms]
    if plan.strong:
        lines.append("Highly specific strings (any one is sufficient to match):")
        lines += [f"  - {_describe(c)}" for c in plan.strong]
    if plan.weak:
        lines.append(f"Supporting strings ({n_of} of these must match together):")
        lines += [f"  - {_describe(c)}" for c in plan.weak]
    lines += [
        "",
        "The condition must be: the hash terms OR'd together, "
        "or any one of the highly specific strings, "
        f"or {n_of} of the supporting strings.",
        "Do not add any indicator that is not listed above.",
    ]
    return "\n".join(lines)


#: Modifier order the describer normalises to. The RULE may say
#: ``nocase fullword``; the description says ``fullword nocase``. Inferred from
#: real describer output, and pinned by test_planformat_matches_describer.
_MOD_ORDER = ("fullword", "nocase", "wide", "xor", "base64", "base64wide")


def _describe_string(cand: Candidate) -> str:
    """One string as the describer words it: value, modifiers, kind."""
    if cand.is_hex:
        return "{ " + " ".join(cand.norm.split()) + " } ascii byte"
    from ..ISB.grammar import DEFAULT_CONFIG, default_modifiers, escape_text
    mods = set(default_modifiers(cand))
    ordered = [m for m in _MOD_ORDER if m in mods]
    if "ascii" not in ordered:
        ordered.append("ascii")          # implicit default, always spelled out
    body = escape_text(cand.value, DEFAULT_CONFIG.hex_escape_non_ascii)
    return f'"{body}" ' + " ".join(ordered) + " string"


def plan_prompt(plan: ConditionPlan, n_of: int | None = None) -> str:
    """Run B: the describer's surface form, emitted straight from the plan.

    No intermediate rule is rendered and RuleDescriber is not called, so this is
    "prompts built directly by the experiment" in the sense EXP1_DESIGN §6 asks
    for -- while still speaking the register the checkpoints were trained on.

    It is NOT guaranteed byte-identical to :func:`describer_prompt`; where the
    two differ, the difference is the experiment. Run A and run B together
    measure how sensitive the generators are to prompt surface form, which is a
    result worth having either way.
    """
    from ..ISB.grammar import render_module_term
    n_of = plan.n_of if n_of is None else n_of
    groups: list[str] = []
    if plan.module_terms:
        terms = [render_module_term(c) for c in plan.module_terms]
        worded = []
        for c, t in zip(plan.module_terms, terms):
            if "imphash" in t:
                worded.append(f'imphash pe equal to "{c.norm}"')
            else:
                worded.append(t)
        groups.append("( " + " or ".join(worded) + " )")
    if plan.strong:
        groups.append("any of the following set ( "
                      + " , ".join(_describe_string(c) for c in plan.strong)
                      + " )")
    if plan.weak:
        groups.append(f"{n_of} of the following set ( "
                      + " , ".join(_describe_string(c) for c in plan.weak)
                      + " )")
    if not groups:
        return "Detect if ( false ) "
    # Left-associative fold, mirroring how the rule's own `or` chain parses.
    # The FIRST combination takes no extra parentheses -- two groups render as
    # "A or B", three as "( A or B ) or C". Verified against real describer
    # output; wrapping the first pair too was a one-paren drift.
    if len(groups) == 1:
        # A single group is not an `or` expression, so it carries no outer
        # parentheses: "Detect if any of the following set ( ... )".
        return f"Detect if {groups[0]} "
    body = groups[0]
    for i, g in enumerate(groups[1:]):
        body = f"{body} or {g}" if i == 0 else f"( {body} ) or {g}"
    return f"Detect if ( {body} ) "


def describer_prompt(rule_source: str, describer: Any = None) -> str:
    """The training-distribution prompt: RuleDescriber's English for a rule.

    Mirrors the working RQ4 pipeline (``rq4_e2e._build_prompts``), which builds a
    template rule and prompts with ``describe_from_string(...)["translation"]
    .iloc[0]["en"]``.
    """
    if describer is None:
        from ..Describer import RuleDescriber
        describer = RuleDescriber()
    frame = describer.describe_from_string(rule_source)
    return frame["translation"].iloc[0]["en"]


_RULE_RE = re.compile(r"\brule\b\s+[A-Za-z_]\w*", re.M)


#: Failures that mean the DEVICE is dead, not that this one unit failed. A CUDA
#: device-side assert poisons the context permanently, so every later call is
#: guaranteed to fail too. Swallowing these turned ONE bad unit into 60 empty
#: rules in the 2026-08-21 bart_scooper run, and the survivors then produced a
#: flattering 98.4% fidelity figure computed over a quarter of the grid.
#: They must abort the run, not degrade it into fake data.
_FATAL_DEVICE_ERRORS = (
    "device-side assert",
    "cuda error",
    "acceleratorerror",
    "out of memory",
    "cublas",
    "no kernel image is available",
)


def _is_fatal_device_error(exc: BaseException) -> bool:
    blob = f"{type(exc).__name__}: {exc}".lower()
    return any(sig in blob for sig in _FATAL_DEVICE_ERRORS)


def _strip_fence(text: str) -> str:
    """Drop a markdown fence. 13 RQ9 cells once scored zero over ```yara."""
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text).strip()
    return text


@dataclass
class LMRuleGenerator:
    """Loads one generator once and renders rules for many families."""

    model: str
    device: str = "cuda"
    verbose: bool = False
    #: Split the selection into chunks of this many candidates, generate one
    #: rule per chunk, and reassemble with the threshold merger. 0 = single
    #: rule from the whole selection. The edge-device path: a 139M model does
    #: not have to hold eight indicators and a condition in one shot.
    chunk_size: int = 0
    #: "describer" (run A: RuleDescriber over the template rule)
    #: "planformat" (run B: same register, emitted straight from the plan)
    #: "handbuilt"  (measured broken -- kept only to report why)
    prompt_style: str = "describer"
    _rg: Any = field(default=None, init=False, repr=False)
    _describer: Any = field(default=None, init=False, repr=False)
    _scooper_kwargs: dict = field(default_factory=dict, init=False, repr=False)
    _max_input_length: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.model not in MODELS:
            raise ValueError(f"unknown model {self.model!r}; have {list(MODELS)}")
        self.cfg = dict(MODELS[self.model])
        self._scooper_kwargs = self._build_scooper_kwargs(self.cfg)

    @staticmethod
    def _build_scooper_kwargs(cfg: Mapping[str, Any]) -> dict[str, Any]:
        """Scooper options for ``RuleGenerator.generate`` (they are generate-time
        parameters, not constructor ones). Relative paths resolve to repo root."""
        if not cfg.get("scooper"):
            return {}
        import os as _os
        root = _os.path.dirname(_os.path.dirname(_os.path.dirname(
            _os.path.abspath(__file__))))
        out: dict[str, Any] = {"scooper": True}
        for key in ("scooper_path", "scooper_tokenizer_path"):
            v = cfg.get(key)
            if v:
                out[key] = v if _os.path.isabs(v) else _os.path.join(root, v)
        if cfg.get("scooper_sequence_length"):
            out["scooper_sequence_length"] = cfg["scooper_sequence_length"]
        return out

    def load(self) -> None:
        if self._rg is not None:
            return
        # Imported here: YaraGen.Inference pulls torch and transformers, and the
        # ISB/RuleSynth packages must stay importable without them.
        from ..Inference import RuleGenerator
        cfg = self.cfg
        kwargs = {
            "model_path": cfg["model_path"],
            "device": self.device,
            "verbose": self.verbose,
            "use_slot_canonicalization": cfg.get("use_slot_canonicalization", False),
        }
        for key in ("tokenizer_path", "yara_tokens_path", "torch_dtype",
                    "system_prompt"):
            if cfg.get(key):
                kwargs[key] = cfg[key]
        self._scooper_kwargs = self._build_scooper_kwargs(cfg)
        if "yara_ast" in cfg:
            kwargs["yara_ast"] = cfg["yara_ast"]
        elif cfg.get("yara_tokens_path"):
            # RQ8 rule: yara_tokens.pkl present == YaraAST checkpoint. Leaving
            # it unset makes RuleGenerator fall back to BASE-tokenizer mode,
            # which the snapshot's own PROVENANCE warns happens SILENTLY.
            kwargs["yara_ast"] = True
        self._rg = RuleGenerator(**kwargs)
        self._rg._initialize()
        # Cap input length at the model's REAL positional limit. BART learns
        # absolute position embeddings with max_position_embeddings=1024, while
        # RuleGenerator.generate defaults max_input_length=4096. An unbudgeted
        # arm (classifier__all__amadey: 512 candidates) overflows that table and
        # the embedding gather trips a CUDA device-side assert, which poisons
        # the context for every later unit. T5-family models use relative
        # positions and report no limit, so they are left alone.
        limit = getattr(getattr(self._rg.model, "config", None),
                        "max_position_embeddings", None)
        if limit:
            self._max_input_length = int(limit)
        cast = cfg.get("cast_dtype")
        if cast:
            # Caller-side only -- RuleGenerator is the shared inference surface
            # for RQ7/8/9 and the e2e experiments and is not modified here
            # (brownie 2026-08-21). Some checkpoints ship mixed dtypes; this
            # makes one model uniform without touching anyone else's path.
            import torch
            self._rg._initialize()
            self._rg.model = self._rg.model.to(getattr(torch, cast))

    def _length_kwargs(self) -> dict[str, Any]:
        return ({"max_input_length": self._max_input_length}
                if self._max_input_length else {})

    def _prompt(self, plan: ConditionPlan, template_source: str | None) -> str:
        if self.prompt_style == "planformat":
            return plan_prompt(plan)
        if self.prompt_style == "describer" and template_source:
            if self._describer is None:
                from ..Describer import RuleDescriber
                self._describer = RuleDescriber()
            try:
                return describer_prompt(template_source, self._describer)
            except Exception:                          # noqa: BLE001
                pass          # fall through rather than lose the unit
        return build_prompt(plan)

    def _chunks(self, plan: ConditionPlan) -> list[ConditionPlan]:
        """Split a plan into sub-plans, keeping the strong/weak split intact.

        Module terms ride along with the first chunk; the merger OR's them back
        in regardless, and duplicating them across chunks would only inflate the
        merged rule.
        """
        n = self.chunk_size
        items = [(c, True) for c in plan.strong] + [(c, False) for c in plan.weak]
        out: list[ConditionPlan] = []
        for i in range(0, len(items), n):
            part = items[i:i + n]
            out.append(ConditionPlan(
                family=plan.family,
                strong=[c for c, s in part if s],
                weak=[c for c, s in part if not s],
                module_terms=plan.module_terms if i == 0 else [],
                reasons=plan.reasons,
                n_weak_required=plan.n_weak_required))
        return out or [plan]

    def _generate_chunked(self, plan: ConditionPlan, arm: str,
                          name: str) -> RenderedRule:
        """The edge path: one small rule per chunk, then a threshold merge.

        This is the RQ4 e2e strategy applied to an ISB selection. Its point is
        not peak quality -- it is that a 139M model on a CPU can reach a usable
        rule, so the pipeline has an answer for deployments that cannot host an
        8B generator. Scooper-ALL keeps the indicator bytes exact; chunking
        keeps each prompt inside what a small model reliably handles; the
        merger restores the condition ISB-B decided on.
        """
        from .template import render_template_rule
        parts, failures = [], Counter()
        for i, sub in enumerate(self._chunks(plan)):
            tpl = render_template_rule(
                sub.family, list(sub.module_terms) + list(sub.strong)
                + list(sub.weak), arm=arm, plan=sub,
                rule_name=f"{name}_c{i}")
            if tpl.is_dead:
                failures["empty_chunk"] += 1
                continue
            prompt = self.cfg.get("prompt_prefix", "") + self._prompt(sub, tpl.source)
            try:
                out = self._rg.generate(
                    prompt, max_new_tokens=self.cfg.get("max_new_tokens", 1024),
                    min_new_tokens=10, num_beams=1, do_sample=False,
                    **self._length_kwargs(), **self._scooper_kwargs)
                text = out[0] if isinstance(out, (list, tuple)) else out
            except Exception as exc:                   # noqa: BLE001
                if _is_fatal_device_error(exc):
                    raise RuntimeError(
                        f"fatal device error on chunk {i} of {name!r} with "
                        f"{self.model}: {type(exc).__name__}: {exc}"
                    ) from exc
                failures[f"generate:{type(exc).__name__}"] += 1
                continue
            text = _strip_fence((text or "").strip())
            if _RULE_RE.search(text):
                parts.append(text)
            else:
                failures["no_rule_emitted"] += 1

        source = self._merge(plan, parts, name)
        dropped = dict(failures)
        dropped["n_chunks"] = len(self._chunks(plan))
        dropped["n_chunks_used"] = len(parts)
        return RenderedRule(
            name=name, source=source + ("\n" if source and not source.endswith("\n") else ""),
            family=plan.family, arm=arm,
            n_strong=len(plan.strong), n_weak=len(plan.weak),
            n_module_terms=len(plan.module_terms), n_of=plan.n_of,
            n_strings=len(re.findall(r"^\s*\$[\w]*\s*=", source, re.M)),
            dropped=dropped, is_dead=not _RULE_RE.search(source or ""))

    def _merge(self, plan: ConditionPlan, texts: Sequence[str],
               name: str) -> str:
        """Threshold-merge per-chunk rules back into one.

        ``is_strong`` is taken from ISB-B's own classification rather than the
        merger's default length heuristic, so the merged condition carries the
        same strong/weak split the selection decided on.
        """
        from ..Merger.Merger import RuleMerger
        strong_norms = {c.norm for c in plan.strong}
        strong_vals = {c.value for c in plan.strong}

        def is_strong(value: str, is_hex: bool) -> bool:
            v = (value or "").strip()
            return v in strong_vals or v.lower() in strong_norms

        texts = [t for t in texts if t and t.strip()]
        if not texts:
            return ""
        if len(texts) == 1:
            return texts[0]
        merged = RuleMerger().merge_rules_threshold(
            {texts[0]: texts[1:]}, is_strong=is_strong,
            n_weak=plan.n_weak_required)
        rules = merged.get("Merged Rules") or []
        return rules[0] if rules else texts[0]

    def generate(
        self,
        plan: ConditionPlan,
        arm: str = "learned",
        rule_name: str | None = None,
        template_source: str | None = None,
    ) -> RenderedRule:
        """One rule for one family. Never raises -- a failure is a recorded row.

        A generator that throws mid-grid would cost the whole run, and "the
        model produced nothing usable" is itself a result the ablation needs.
        """
        self.load()
        name = sanitize_rule_name(
            rule_name or f"ISB_{self.model}_{arm}_{plan.family}")

        if self.chunk_size:
            return self._generate_chunked(plan, arm, name)

        prompt = self.cfg.get("prompt_prefix", "") + self._prompt(
            plan, template_source)
        try:
            out = self._rg.generate(
                prompt,
                max_new_tokens=self.cfg.get("max_new_tokens", 1024),
                min_new_tokens=10, num_beams=1, do_sample=False,
                **self._length_kwargs(), **self._scooper_kwargs)
            text = out[0] if isinstance(out, (list, tuple)) else out
        except Exception as exc:                       # noqa: BLE001
            if _is_fatal_device_error(exc):
                # The accelerator is unusable from here on; a per-unit "empty
                # rule" would be a lie about every remaining unit.
                raise RuntimeError(
                    f"fatal device error while generating {name!r} with "
                    f"{self.model}: {type(exc).__name__}: {exc}. The CUDA "
                    f"context is poisoned -- every subsequent unit would fail "
                    f"identically, so the run is aborted rather than filled "
                    f"with empty rules."
                ) from exc
            return RenderedRule(
                name=name, source="", family=plan.family, arm=arm,
                dropped={f"generate_error:{type(exc).__name__}": 1},
                is_dead=True)

        text = _strip_fence((text or "").strip())

        rendered = RenderedRule(
            name=name, source=text + ("\n" if text and not text.endswith("\n") else ""),
            family=plan.family, arm=arm,
            n_strong=len(plan.strong), n_weak=len(plan.weak),
            n_module_terms=len(plan.module_terms), n_of=plan.n_of,
            n_strings=len(re.findall(r"^\s*\$[\w]*\s*=", text, re.M)),
            is_dead=not _RULE_RE.search(text))
        if rendered.is_dead:
            rendered.dropped["no_rule_emitted"] = 1
        return rendered

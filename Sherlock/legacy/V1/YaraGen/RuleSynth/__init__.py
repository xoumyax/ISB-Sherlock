"""Rule synthesis: an ISB selection -> a compilable YARA rule.

``template`` is the deterministic, no-LM control (EXP2_DESIGN §9). It renders the
ISB-B condition plan exactly, so any TPR/FP difference between arms is
attributable to *selection* rather than to a language model's variance.

``llm`` is the deliverable: the trained YaraGen generators (BART, Ministral-8B,
Llama-8B TaskMix) writing the rule from the same plan, with the prompt
decorations their training used.
"""

from .template import RenderedRule, YARA_MAX_STRINGS, render_template_rule

__all__ = ["RenderedRule", "render_template_rule", "YARA_MAX_STRINGS",
           "MODELS", "build_prompt", "LMRuleGenerator", "RQ9_SYSTEM_PROMPT"]


def __getattr__(name):
    # Lazy: llm.py imports YaraGen.Inference, which pulls torch and
    # transformers. `from YaraGen.RuleSynth import render_template_rule` must
    # stay cheap enough for the ISB tests to import it without a GPU stack.
    if name in ("MODELS", "build_prompt", "LMRuleGenerator", "RQ9_SYSTEM_PROMPT"):
        from . import llm
        return getattr(llm, name)
    raise AttributeError(name)

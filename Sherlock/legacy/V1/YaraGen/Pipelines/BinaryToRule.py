"""One call: malware samples in, a YARA rule out (EXP2 pipeline, end to end).

``BinaryToRule().generate(paths)`` runs the whole Exp-2 spine --

    static extraction -> candidate emission -> family pooling -> ISB-A scoring
    -> type_cover budget -> ISB-B condition plan -> rule

-- so the future threat-hunt agent can ask for a rule without knowing that any
of those stages exist. This supersedes the old ``RuleGeneratorIOC`` stub, which
imported a ``YaraGen.Models`` module that does not exist and could never have
run.

**The goodware indexes are the difference between a rule and a liability.**
Every hygiene decision in the pipeline -- what lint drops, what counts as a
"strong" term that may fire alone -- is a question about whether a value occurs
in benign software. With no index loaded, every candidate looks clean, every
literal is promoted to strong, and the result is the permissive rule that
matched 5/5 goodware in the pre-wipe incident. So:

* ``strict=True`` (default) **raises** when no goodware index is available.
* ``strict=False`` proceeds and stamps ``goodware_verified: false`` into the
  rule's own metadata, so an unvetted rule cannot be mistaken for a vetted one
  later.

Optional stages degrade rather than fail: no classifier checkpoint means no
``HEX_SPAN`` candidates (static-only, the ``static`` arm of the ablation), and
no trained scorer means the deterministic ``PriorScorer`` -- a known baseline
rather than noise.

SAFETY: samples are read statically (``open(rb)``, ``pefile``). Nothing is
executed. The corpus this is pointed at is live malware.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Sequence

from ..ISB.budget import BudgetConfig, apply_budget
from ..ISB.candidate import Candidate
from ..ISB.condition import ConditionBrain, ConditionConfig
from ..ISB.goodware import GoodwareOracle
from ..ISB.grammar import filter_expressible
from ..ISB.pooling import DFIndex, FamilyCandidateSet
from ..ISB.salience import PriorScorer, SalienceScorer
from ..ISB.stoplist import Stoplist
from ..RuleSynth.template import RenderedRule, render_template_rule

__all__ = ["BinaryToRuleConfig", "BinaryToRule"]


@dataclass
class BinaryToRuleConfig:
    #: Goodware document-frequency index (StaticFeatures/dfindex.py). Strongly
    #: recommended; see the module docstring for what happens without it.
    df_index_path: str | None = None
    #: Byte-substring presence index (StaticFeatures/presence.py). The only
    #: thing that can score a HEX_SPAN, and the only genericity test that
    #: measures what YARA actually matches on.
    span_index_path: str | None = None
    #: Trained ISB-A scorer directory; falls back to PriorScorer when absent.
    salience_dir: str | None = None
    #: Byte-CNN checkpoint for attributed HEX_SPAN candidates (optional).
    classifier_path: str | None = None
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    condition: ConditionConfig = field(default_factory=ConditionConfig)
    #: Refuse to build a rule with no goodware evidence at all.
    strict: bool = True
    device: str = "cpu"


class BinaryToRule:
    """The Exp-2 spine behind one method call."""

    def __init__(self, config: BinaryToRuleConfig | None = None):
        self.config = config or BinaryToRuleConfig()
        self.oracle = self._load_oracle()
        self.stoplist = Stoplist()
        self.brain = ConditionBrain(self.oracle, self.config.condition)
        self.scorer = self._load_scorer()

    # -- wiring --------------------------------------------------------
    def _load_oracle(self) -> GoodwareOracle:
        cfg = self.config
        strings = spans = None
        if cfg.df_index_path and os.path.exists(cfg.df_index_path):
            from ..StaticFeatures.dfindex import load_df_index
            strings, _ = load_df_index(cfg.df_index_path)
        if cfg.span_index_path and os.path.exists(cfg.span_index_path):
            from ..StaticFeatures.spanindex import load_span_df
            spans = load_span_df(cfg.span_index_path)
        oracle = GoodwareOracle(strings=strings, spans=spans)
        if cfg.strict and not any(oracle.scored_types.values()):
            raise RuntimeError(
                "no goodware index available. Every candidate would look "
                "absent-from-goodware, every literal would be promoted to a "
                "fire-alone term, and the rule would match benign software. "
                "Pass df_index_path/span_index_path, or set strict=False to "
                "accept an explicitly unverified rule.")
        return oracle

    def _load_scorer(self):
        cfg = self.config
        if not cfg.salience_dir:
            return PriorScorer(self.oracle)
        model = os.path.join(cfg.salience_dir, "salience.txt")
        if not os.path.exists(model):
            return PriorScorer(self.oracle)
        import json
        import lightgbm as lgb
        scorer = SalienceScorer(self.oracle)
        scorer.model = lgb.Booster(model_file=model)
        meta_path = os.path.join(cfg.salience_dir, "salience.meta.json")
        if os.path.exists(meta_path):
            with open(meta_path) as fh:
                scorer.feature_names = json.load(fh).get("feature_names", [])
        # Booster.predict returns P(positive) directly, unlike the sklearn
        # wrapper's two-column proba; adapt rather than mis-index column 1.
        booster = scorer.model

        def _score(pooled):
            if not pooled:
                return []
            rows = [scorer.featurize(p) for p in pooled]
            return [float(v) for v in booster.predict(scorer._matrix(rows))]

        scorer.score = _score            # type: ignore[method-assign]
        return scorer

    # -- stages --------------------------------------------------------
    def candidates(self, paths: Sequence[str]) -> FamilyCandidateSet:
        """Static extraction + emission, plus attributed spans when available."""
        from ..StaticFeatures.emit import EmitConfig, record_to_candidates
        from ..StaticFeatures.extract import extract_record

        emit_cfg = EmitConfig()
        per_sha: dict[str, list[Candidate]] = {}
        sha_path: dict[str, str] = {}
        for path in paths:
            rec = extract_record(path)            # never raises
            sha = rec.get("sha256") or os.path.basename(path)
            sha_path[sha] = path
            per_sha[sha] = list(record_to_candidates(rec, emit_cfg))

        if self.config.classifier_path and os.path.exists(self.config.classifier_path):
            self._add_spans(per_sha, sha_path)

        # add_sample REPLACES a sample's candidate set, so static and attributed
        # candidates are merged first and added once. Adding them in two calls
        # would silently discard the static half.
        fcs = FamilyCandidateSet("target")
        for sha, cands in per_sha.items():
            fcs.add_sample(sha, cands)
        return fcs

    def _add_spans(self, per_sha, sha_path) -> None:
        from ..SampleClassifier.attribute import Attributor, AttributionConfig
        from ..SampleClassifier.data import SampleRef, WindowSampler
        from ..SampleClassifier.emit_spans import SpanEmitConfig, emit_family_spans
        from ..SampleClassifier.train import load_checkpoint

        model, blob = load_checkpoint(self.config.classifier_path,
                                      device=self.config.device)
        attr = Attributor(model, WindowSampler(**blob["sampler"]),
                          blob["family_names"], config=AttributionConfig(),
                          device=self.config.device)
        refs = [SampleRef(sha256=sha, path=path, label=1, family=None,
                          family_index=-1, origin="query", meta={})
                for sha, path in sha_path.items()]
        result = emit_family_spans(attr, "target", refs, SpanEmitConfig())
        for sha, cands in result["per_sample"].items():
            if cands:
                per_sha.setdefault(sha, []).extend(cands)

    # -- entry point ---------------------------------------------------
    def generate(
        self,
        sample_paths: Sequence[str],
        family_hint: str | None = None,
        arm: str = "learned",
    ) -> dict[str, Any]:
        """Samples -> one rule, plus the evidence behind every choice."""
        if not sample_paths:
            raise ValueError("no samples given")
        family = family_hint or "unknown_family"

        fcs = self.candidates(sample_paths)
        pooled = fcs.pool(df_index=self.oracle.strings)

        expr, dropped = [], {}
        kept, drop_map = filter_expressible([p.candidate for p in pooled])
        keep_norms = {c.norm for c in kept}
        dropped.update({k: len(v) for k, v in drop_map.items()})
        for p in pooled:
            if p.candidate.norm not in keep_norms:
                continue
            hit = self.stoplist.hits(p.candidate)
            if hit:
                dropped[hit] = dropped.get(hit, 0) + 1
                continue
            if self.oracle.verdict(p.candidate).count > 0:
                dropped["goodware_generic"] = dropped.get("goodware_generic", 0) + 1
                continue
            expr.append(p)

        ranked = self.scorer.rank(expr) if hasattr(self.scorer, "rank") else expr
        budgeted = apply_budget(ranked, self.config.budget)
        selected: list[Candidate] = [p.candidate for p in budgeted["selected"]]
        plan = self.brain.plan(family, selected)
        rule: RenderedRule = render_template_rule(
            family, selected, arm=arm, brain=self.brain, plan=plan)

        verified = any(self.oracle.scored_types.values())
        source = rule.source
        if not verified and source:
            source = source.replace(
                '        generator = "template"',
                '        generator = "template"\n'
                '        goodware_verified = "false"')
        return {
            "rule": source,
            "family": family,
            "n_samples": fcs.n_samples,
            "n_candidates": len(pooled),
            "n_after_hygiene": len(expr),
            "selected": [c.to_dict() for c in selected],
            "condition": plan.summary(),
            "dropped": dropped,
            "budget": {k: v for k, v in budgeted.items() if k != "selected"},
            "goodware_verified": verified,
            "goodware_indexes": self.oracle.scored_types,
            "scorer": getattr(self.scorer, "name", "prior"),
            "is_dead": rule.is_dead,
        }

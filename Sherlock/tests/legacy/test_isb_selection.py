"""M3 tests: goodware routing, supervision, salience, budget, condition, arms.

Companion to ``test_isb_core.py`` (M0). Everything here is synthetic and
hermetic -- no corpus paths, no checkpoints -- except the yara span-index tests,
which write their own tiny files into ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from YaraGen.ISB.budget import BudgetConfig, apply_budget, type_cover
from YaraGen.ISB.candidate import Candidate, CType
from YaraGen.ISB.condition import ConditionBrain, ConditionConfig
from YaraGen.ISB.goodware import GoodwareOracle, GoodwareVerdict
from YaraGen.ISB.isb import ARMS, ISB, ISBConfig
from YaraGen.ISB.pooling import DFIndex, FamilyCandidateSet, PooledCandidate
from YaraGen.ISB.salience import PriorScorer, SalienceConfig, SalienceScorer
from YaraGen.ISB.supervision import (
    SupervisionConfig,
    build_training_table,
    label_family,
)


# ---------------------------------------------------------------- helpers

def C(value, ctype=CType.STRING_ASCII, **attrs):
    return Candidate(value=value, ctype=ctype, source="test", attrs=attrs)


def HEX(body):
    return Candidate(value=body, ctype=CType.HEX_SPAN, source="test")


def family_set(name, samples):
    """samples: {sha: [Candidate, ...]}"""
    fcs = FamilyCandidateSet(name)
    for sha, cands in samples.items():
        fcs.add_sample(sha, cands)
    return fcs


def pooled(cand, n_containing=5, n_samples=10, **kw):
    return PooledCandidate(
        candidate=cand, n_containing=n_containing, n_samples=n_samples, **kw)


# ------------------------------------------------------- goodware oracle

def test_oracle_routes_hex_to_span_index():
    strings = DFIndex(df={"anything": 1}, n_docs=100)
    spans = DFIndex(df={"21 b8 01 4c": 7}, n_docs=50)
    oracle = GoodwareOracle(strings=strings, spans=spans)
    v = oracle.verdict(HEX("21 B8 01 4C"))
    assert v.index == "spans" and v.count == 7 and v.n_docs == 50


def test_oracle_routes_strings_to_string_index():
    oracle = GoodwareOracle(
        strings=DFIndex(df={"kernel32.dll": 900}, n_docs=1000),
        spans=DFIndex(df={}, n_docs=50))
    v = oracle.verdict(C("kernel32.dll", CType.IMPORT))
    assert v.index == "strings" and v.count == 900


def test_oracle_hex_without_span_index_reports_unscored_not_clean():
    """The bug this module exists to prevent: a hex span must never come back
    as a confident zero just because nobody could score it."""
    oracle = GoodwareOracle(strings=DFIndex(df={"x": 1}, n_docs=100))
    v = oracle.verdict(HEX("21 B8 01 4C CD 21 54 68"))
    assert v.index == "none"
    assert v.count == 0
    assert v.absent is False           # <- not "clean"
    assert oracle.is_absent(HEX("21 B8 01 4C CD 21 54 68")) is False


def test_oracle_absent_requires_a_nonempty_index():
    assert GoodwareVerdict(count=0, n_docs=0, index="none").absent is False
    assert GoodwareVerdict(count=0, n_docs=10, index="strings").absent is True
    assert GoodwareVerdict(count=1, n_docs=10, index="strings").absent is False


def test_oracle_scored_types_reports_both_halves():
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=5))
    assert oracle.scored_types == {"strings": True, "spans": False}


def test_oracle_verdict_rate_uses_originating_index_n_docs():
    oracle = GoodwareOracle(
        strings=DFIndex(df={"a": 50}, n_docs=100),
        spans=DFIndex(df={"aa bb": 1}, n_docs=4))
    assert oracle.verdict(C("a")).rate == pytest.approx(0.5)
    assert oracle.verdict(HEX("AA BB")).rate == pytest.approx(0.25)


def test_oracle_span_key_is_casefolded():
    oracle = GoodwareOracle(spans=DFIndex(df={"de ad be ef": 3}, n_docs=9))
    assert oracle.count(HEX("DE AD BE EF")) == 3


# ----------------------------------------------------------- supervision

def _three_sample_family():
    shared = C("SharedMarkerStringXYZ")
    rare = C("only-here")
    generic = C("kernel32.dll", CType.IMPORT)
    return family_set("fam", {
        "a": [shared, generic],
        "b": [shared, generic],
        "c": [shared, rare, generic],
    }), shared, rare, generic


def test_supervision_positive_needs_support_and_goodware_absence():
    fcs, shared, rare, generic = _three_sample_family()
    oracle = GoodwareOracle(
        strings=DFIndex(df={"kernel32.dll": 900}, n_docs=1000))
    labels = label_family(fcs, oracle, SupervisionConfig(), m=2)
    assert shared.key() in labels.positives
    assert rare.key() in labels.negatives          # support 1 < m
    assert generic.key() in labels.negatives       # goodware present
    assert labels.denied[generic.key()] == "goodware_present"
    assert labels.denied[rare.key()] == "support_below_m"


def test_supervision_m_defaults_to_pooling_rule():
    fcs, *_ = _three_sample_family()
    labels = label_family(fcs, GoodwareOracle(strings=DFIndex(df={}, n_docs=5)))
    assert labels.m == FamilyCandidateSet.default_m(3)


def test_supervision_matches_positive_keys_when_strings_only():
    """The documented deviation is *only* the routing; with no hex involved the
    two must agree exactly, or supervision has silently changed the label rule."""
    fcs, *_ = _three_sample_family()
    df = DFIndex(df={"kernel32.dll": 900}, n_docs=1000)
    mine = label_family(fcs, GoodwareOracle(strings=df), m=2).positives
    theirs = fcs.positive_keys(m=2, df_index=df)
    assert mine == theirs


def test_supervision_refuses_hex_without_span_index():
    span = HEX("21 B8 01 4C CD 21 54 68")
    fcs = family_set("fam", {"a": [span], "b": [span], "c": [span]})
    labels = label_family(
        fcs, GoodwareOracle(strings=DFIndex(df={}, n_docs=10)), m=2)
    assert span.key() not in labels.positives
    assert labels.denied[span.key()] == "no_span_index"


def test_supervision_labels_hex_when_span_index_present():
    span = HEX("21 B8 01 4C CD 21 54 68")
    fcs = family_set("fam", {"a": [span], "b": [span], "c": [span]})
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=10),
                            spans=DFIndex(df={}, n_docs=10))
    labels = label_family(fcs, oracle, m=2)
    assert span.key() in labels.positives


def test_supervision_goodware_hex_span_becomes_negative():
    span = HEX("5F 5F 76 62 61 53 74 72")
    fcs = family_set("fam", {"a": [span], "b": [span], "c": [span]})
    oracle = GoodwareOracle(
        strings=DFIndex(df={}, n_docs=10),
        spans=DFIndex(df={"5f 5f 76 62 61 53 74 72".lower(): 36}, n_docs=42))
    labels = label_family(fcs, oracle, m=2)
    assert span.key() in labels.negatives
    assert labels.denied[span.key()] == "goodware_present"


def test_supervision_max_goodware_df_knob_is_respected():
    c = C("SomeMarkerValueHere")
    fcs = family_set("fam", {"a": [c], "b": [c]})
    # DFIndex case-folds the probe, so index keys are stored folded.
    oracle = GoodwareOracle(strings=DFIndex(df={c.norm.lower(): 1}, n_docs=100))
    strict = label_family(fcs, oracle, SupervisionConfig(), m=2)
    loose = label_family(fcs, oracle, SupervisionConfig(max_goodware_df=1), m=2)
    assert c.key() in strict.negatives
    assert c.key() in loose.positives


def test_supervision_summary_counts_add_up():
    fcs, *_ = _three_sample_family()
    labels = label_family(
        fcs, GoodwareOracle(strings=DFIndex(df={"kernel32.dll": 9}, n_docs=99)),
        m=2)
    s = labels.summary()
    assert s["n_positive"] + s["n_negative"] == len(
        labels.positives | labels.negatives)
    assert 0.0 <= s["positive_rate"] <= 1.0


def test_training_table_requires_the_leakage_guard():
    fcs, *_ = _three_sample_family()
    with pytest.raises(ValueError, match="allowed_families is required"):
        build_training_table([fcs], {}, GoodwareOracle())


def test_training_table_raises_on_non_f_train_family():
    fcs = family_set("njrat", {"a": [C("SomeValueHereLong")]})
    with pytest.raises(AssertionError, match="LEAKAGE"):
        build_training_table([fcs], {}, GoodwareOracle(),
                             allowed_families=["loki", "gozi"])


def test_training_table_joins_features_and_labels():
    fcs, shared, rare, generic = _three_sample_family()
    oracle = GoodwareOracle(
        strings=DFIndex(df={"kernel32.dll": 900}, n_docs=1000))
    pool = {"fam": [pooled(shared, 3, 3), pooled(rare, 1, 3),
                    pooled(generic, 3, 3)]}
    table = build_training_table([fcs], pool, oracle, allowed_families=["fam"])
    assert len(table["rows"]) == len(table["labels"]) == 3
    assert table["summary"]["n_positive"] == 1
    assert set(table["groups"]) == {"fam"}
    assert "goodware_rate" in table["feature_names"]
    assert "goodware_df" not in table["feature_names"]


def test_training_table_restates_goodware_rate_from_oracle():
    """Pooling may have been handed only the string index; the table must not
    inherit a structural zero for a span."""
    span = HEX("5F 5F 76 62 61 53 74 72")
    fcs = family_set("fam", {"a": [span], "b": [span]})
    oracle = GoodwareOracle(
        strings=DFIndex(df={}, n_docs=10),
        spans=DFIndex(df={span.norm.lower(): 36}, n_docs=42))
    pool = {"fam": [pooled(span, 2, 2, goodware_df=0, goodware_n_docs=10)]}
    table = build_training_table([fcs], pool, oracle, allowed_families=["fam"])
    assert table["rows"][0]["goodware_rate"] == pytest.approx(36 / 42)


def test_training_table_drops_unlabelled_rows_rather_than_defaulting():
    span = HEX("21 B8 01 4C CD 21 54 68")
    fcs = family_set("fam", {"a": [span], "b": [span]})
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=10))   # no span index
    pool = {"fam": [pooled(span, 2, 2)]}
    table = build_training_table([fcs], pool, oracle, allowed_families=["fam"])
    assert table["rows"] == []          # not silently negative
    assert table["summary"]["goodware_scored"]["spans"] is False


# --------------------------------------------------------------- budget

def test_type_cover_round_robins_across_types():
    ranked = [pooled(C(f"aaaa{i}", CType.STRING_ASCII)) for i in range(5)] + \
             [pooled(C(f"bbbb{i}", CType.MUTEX)) for i in range(5)]
    picked = type_cover(ranked, k=4, exclude_types=frozenset())
    assert [p.candidate.ctype for p in picked] == [
        CType.STRING_ASCII, CType.MUTEX, CType.STRING_ASCII, CType.MUTEX]


def test_type_cover_respects_k():
    ranked = [pooled(C(f"aaaa{i}")) for i in range(20)]
    assert len(type_cover(ranked, k=8, exclude_types=frozenset())) == 8


def test_type_cover_prevalent_hashes_are_free_and_uncounted():
    h = Candidate(value="a" * 64, ctype=CType.HASH_SHA256, source="t")
    ranked = [pooled(h, 10, 10)] + [pooled(C(f"aaaa{i}")) for i in range(10)]
    picked = type_cover(ranked, k=3)
    assert h in [p.candidate for p in picked]
    assert len([p for p in picked if p.candidate.ctype != CType.HASH_SHA256]) == 3


def test_low_prevalence_hashes_lose_their_exemption():
    """A sha256 carried by one gen sample cannot match anything held out; the
    exemption made rules into 59-term hash blocklists."""
    lone = Candidate(value="b" * 64, ctype=CType.HASH_SHA256, source="t")
    shared = Candidate(value="c" * 32, ctype=CType.HASH_IMPHASH, source="t")
    ranked = [pooled(lone, 1, 88), pooled(shared, 80, 88)]
    picked = [p.candidate for p in type_cover(ranked, k=8)]
    assert shared in picked and lone not in picked


def test_budget_reports_how_many_free_terms_the_gate_rejected():
    lone = [pooled(Candidate(value=f"{i:064x}", ctype=CType.HASH_SHA256,
                             source="t"), 1, 88) for i in range(59)]
    out = apply_budget(lone + [pooled(C("SomeMarkerValue"), 40, 88)])
    assert out["n_free_rejected"] == 59
    assert out["n_free"] == 0


def test_type_cover_stops_when_pool_exhausted():
    ranked = [pooled(C("aaaa")), pooled(C("bbbb"))]
    assert len(type_cover(ranked, k=8, exclude_types=frozenset())) == 2


def test_type_cover_is_stable_for_a_given_ranking():
    ranked = [pooled(C(f"aaaa{i}")) for i in range(6)] + \
             [pooled(C(f"mmmm{i}", CType.MUTEX)) for i in range(6)]
    assert type_cover(ranked, k=5) == type_cover(ranked, k=5)


def test_apply_budget_reports_accounting():
    ranked = [pooled(C(f"aaaa{i}")) for i in range(10)] + \
             [pooled(C(f"mmmm{i}", CType.MUTEX)) for i in range(3)]
    out = apply_budget(ranked, BudgetConfig(k=6))
    assert out["n_input"] == 13 and out["k"] == 6
    assert out["n_budgeted"] == 6
    assert out["types_used"] == 2
    assert out["policy"] == "type_cover"


def test_top_k_policy_is_not_available():
    """It is banned, not missing (pre-wipe FP 853/1k)."""
    import YaraGen.ISB.budget as B
    assert not hasattr(B, "top_k")


# ------------------------------------------------------------- condition

def test_hex_with_eight_fixed_bytes_is_strong():
    brain = ConditionBrain()
    strong, why = brain.is_strong(HEX("21 B8 01 4C CD 21 54 68"))
    assert strong and why.startswith("hex_fixed_bytes")


def test_hex_with_seven_fixed_bytes_is_weak():
    brain = ConditionBrain()
    strong, why = brain.is_strong(HEX("21 B8 01 4C CD 21 54"))
    assert not strong and why.startswith("hex_too_short")


def test_wildcards_do_not_count_toward_hex_strength():
    brain = ConditionBrain()
    strong, _ = brain.is_strong(HEX("21 B8 ?? ?? ?? ?? ?? ?? ?? ??"))
    assert not strong


def test_long_literal_absent_from_goodware_is_strong():
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=500))
    brain = ConditionBrain(oracle)
    strong, why = brain.is_strong(C("UniqueMarkerStringForFamily"))
    assert strong and "goodware_absent" in why


def test_long_literal_present_in_goodware_is_weak():
    c = C("This program cannot be run")
    oracle = GoodwareOracle(strings=DFIndex(df={c.norm.lower(): 277}, n_docs=300))
    strong, why = ConditionBrain(oracle).is_strong(c)
    assert not strong and why == "goodware_df:277"


def test_unverified_absence_does_not_promote_to_strong():
    """With no index every literal would look clean; promoting on that restores
    the catastrophic OR behaviour this module exists to prevent."""
    brain = ConditionBrain(GoodwareOracle())          # empty oracle
    strong, why = brain.is_strong(C("UniqueMarkerStringForFamily"))
    assert not strong and why == "absence_unverified"


def test_short_literal_is_weak_regardless_of_goodware():
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=500))
    strong, why = ConditionBrain(oracle).is_strong(C("short"))
    assert not strong and why.startswith("literal_short")


def test_plan_splits_module_terms_out():
    h = Candidate(value="b" * 64, ctype=CType.HASH_SHA256, source="t")
    brain = ConditionBrain(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)))
    plan = brain.plan("fam", [h, C("UniqueMarkerStringForFamily"), C("short")])
    assert plan.module_terms == [h]
    assert len(plan.strong) == 1 and len(plan.weak) == 1


def test_single_weak_string_fires_alone():
    """HANDOFF lesson: N=min(2,#weak), so one weak candidate gives 1-of. The
    alternative -- demanding 2-of -- makes the group unsatisfiable and silently
    deletes it from the rule."""
    brain = ConditionBrain(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)))
    plan = brain.plan("fam", [C("short")])
    assert plan.n_of == 1
    assert plan.summary()["fires_on_single_weak"] is True
    cond = brain.render_condition(plan, [], ["$w0"])
    assert cond == "1 of ($w0)"


def test_condition_never_renders_any_of_them():
    brain = ConditionBrain(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)))
    plan = brain.plan("fam", [C("UniqueMarkerStringForFamily"),
                              C("shortA"), C("shortB")])
    cond = brain.render_condition(plan, ["$s0"], ["$w0", "$w1"])
    assert "any of them" not in cond
    assert "any of ($s0)" in cond and "2 of ($w0, $w1)" in cond


def test_condition_with_nothing_renders_false_not_empty():
    brain = ConditionBrain()
    plan = brain.plan("fam", [])
    assert brain.render_condition(plan, [], []) == "false"
    assert plan.is_empty()


def test_prompt_terms_carry_the_shape():
    brain = ConditionBrain(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)))
    plan = brain.plan("fam", [C("UniqueMarkerStringForFamily"), C("shortA")])
    terms = brain.prompt_terms(plan)
    assert terms["strong"] and terms["weak"] and terms["n_of"] == 1
    assert "N of weak" in terms["shape"]


# -------------------------------------------------------------- salience

def test_prior_scorer_prefers_prevalent_and_clean():
    oracle = GoodwareOracle(strings=DFIndex(df={"generic": 500}, n_docs=1000))
    clean, dirty = C("CleanMarkerValue"), C("generic")
    ps = PriorScorer(oracle)
    assert ps.score_one(pooled(clean, 9, 10)) > ps.score_one(pooled(dirty, 9, 10))


def test_prior_scorer_penalises_promiscuity():
    ps = PriorScorer(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)))
    a = pooled(C("MarkerA"), 9, 10, xfam_promiscuity=0)
    b = pooled(C("MarkerB"), 9, 10, xfam_promiscuity=12)
    assert ps.score_one(a) > ps.score_one(b)


def test_scorer_falls_back_when_positives_are_too_few():
    s = SalienceScorer(config=SalienceConfig(min_positives=30))
    summary = s.fit([{"prevalence": 1.0}] * 10, [1] * 3 + [0] * 7)
    assert summary["fitted"] is False
    assert summary["reason"] == "insufficient_positives"
    assert s.score([pooled(C("x"))])          # still scores, via the prior


def test_scorer_fallback_has_no_importances():
    s = SalienceScorer(config=SalienceConfig(min_positives=99))
    s.fit([{"prevalence": 1.0}] * 4, [1, 0, 1, 0])
    assert s.feature_importances() == {}


def test_scorer_fits_and_ranks_when_labels_suffice():
    rows, labels = [], []
    for i in range(120):
        pos = i % 2 == 0
        rows.append({"prevalence": 0.9 if pos else 0.1,
                     "goodware_df": 0.0 if pos else 50.0,
                     "length": 20.0})
        labels.append(1 if pos else 0)
    s = SalienceScorer(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)),
                       SalienceConfig(min_positives=10, n_estimators=20))
    summary = s.fit(rows, labels)
    assert summary["fitted"] is True
    imps = s.feature_importances()
    assert set(imps) == {"prevalence", "goodware_df", "length"}


def test_scorer_rank_is_deterministic():
    s = SalienceScorer(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)))
    ps = [pooled(C(f"Marker{i}"), i, 10) for i in range(6)]
    assert [p.candidate.norm for p in s.rank(ps)] == \
           [p.candidate.norm for p in s.rank(ps)]


def test_scorer_save_writes_meta_without_a_model(tmp_path):
    s = SalienceScorer(config=SalienceConfig(min_positives=99))
    s.fit([{"prevalence": 1.0}] * 4, [1, 0, 1, 0])
    paths = s.save(str(tmp_path))
    assert "model" not in paths
    blob = json.load(open(paths["meta"]))
    assert blob["train_summary"]["fitted"] is False


# ------------------------------------------------------------- arm ladder

def _arm_pool():
    oracle = GoodwareOracle(
        strings=DFIndex(df={"kernel32.dll": 900}, n_docs=1000),
        spans=DFIndex(df={}, n_docs=100))
    ps = [
        pooled(C("UniqueMarkerStringOne"), 9, 10),
        pooled(C("UniqueMarkerStringTwo"), 8, 10),
        pooled(C("kernel32.dll", CType.IMPORT), 10, 10),
        pooled(C("MutexNameHere", CType.MUTEX), 7, 10),
        pooled(HEX("21 B8 01 4C CD 21 54 68"), 6, 10),
    ]
    return oracle, ps


def test_all_arm_is_unbudgeted_and_unlinted():
    oracle, ps = _arm_pool()
    sel = ISB(oracle).run_arm("fam", ps, "all")
    assert sel.stats["budgeted"] is False
    assert any(c.ctype == CType.IMPORT for c in sel.selected)  # generic kept


def test_lint_arm_drops_stoplisted_values():
    """kernel32.dll is curated-stoplisted, so it never reaches the DF check --
    that layering is deliberate (generic PE/system names are sub-min_len for the
    index and would otherwise slip through)."""
    oracle, ps = _arm_pool()
    sel = ISB(oracle).run_arm("fam", ps, "lint")
    assert all(c.norm != "kernel32.dll" for c in sel.selected)
    assert "system_dll" in sel.dropped
    assert sel.stats["budgeted"] is False


def test_lint_arm_drops_goodware_generic_values():
    """A value the stoplist does not know about, but goodware carries."""
    generic = C("SomeVeryCommonInstallerString")
    oracle = GoodwareOracle(
        strings=DFIndex(df={generic.norm.lower(): 400}, n_docs=1000))
    sel = ISB(oracle).run_arm("fam", [pooled(generic, 9, 10)], "lint")
    assert sel.selected == []
    assert "goodware_generic" in sel.dropped


def test_prevalence_k_ranks_by_prevalence_and_budgets():
    oracle, ps = _arm_pool()
    sel = ISB(oracle, config=ISBConfig(budget=BudgetConfig(k=2))).run_arm(
        "fam", ps, "prevalence_k")
    assert sel.stats["budgeted"] is True
    assert sel.stats["n_budgeted"] == 2


def test_random_k_requires_a_size_match():
    oracle, ps = _arm_pool()
    with pytest.raises(ValueError, match="size-matched"):
        ISB(oracle).run_arm("fam", ps, "random_k")


def test_random_k_is_size_matched_to_learned_in_the_ladder():
    oracle, ps = _arm_pool()
    out = ISB(oracle).run_ladder("fam", ps, arms=("learned", "random_k"))
    assert out["random_k"].stats["n_budgeted"] == out["learned"].stats["n_budgeted"]
    assert out["random_k"].stats["policy"] == "random_post_lint"


def test_random_k_is_drawn_post_lint():
    oracle, ps = _arm_pool()
    out = ISB(oracle).run_ladder("fam", ps, arms=("learned", "random_k"))
    assert all(c.norm != "kernel32.dll" for c in out["random_k"].selected)


def test_random_k_is_seeded_per_family():
    oracle, ps = _arm_pool()
    isb = ISB(oracle)
    a = isb.run_arm("fam", ps, "random_k", size_match=2)
    b = isb.run_arm("fam", ps, "random_k", size_match=2)
    assert [c.norm for c in a.selected] == [c.norm for c in b.selected]


def test_oracle_peek_requires_the_truth_it_peeks_at():
    oracle, ps = _arm_pool()
    with pytest.raises(ValueError, match="oracle_hits"):
        ISB(oracle).run_arm("fam", ps, "oracle_peek")


def test_oracle_peek_is_flagged_as_peeking():
    oracle, ps = _arm_pool()
    sel = ISB(oracle).run_arm(
        "fam", ps, "oracle_peek",
        oracle_hits=lambda c: c.norm.startswith("uniquemarkerstringtwo"))
    assert sel.peeked is True
    assert sel.summary()["peeked"] is True


def test_no_other_arm_is_flagged_as_peeking():
    oracle, ps = _arm_pool()
    isb = ISB(oracle)
    for arm in ("all", "lint", "prevalence_k", "learned"):
        assert isb.run_arm("fam", ps, arm).peeked is False


def test_unknown_arm_raises():
    oracle, ps = _arm_pool()
    with pytest.raises(ValueError, match="unknown arm"):
        ISB(oracle).run_arm("fam", ps, "magic")


def test_ladder_covers_every_available_arm():
    oracle, ps = _arm_pool()
    out = ISB(oracle).run_ladder("fam", ps, arms=ARMS,
                                 oracle_hits=lambda c: True)
    # `analyst` needs mining.py and is skipped, not faked.
    assert set(out) == set(ARMS) - {"analyst"}


def test_analyst_arm_raises_rather_than_mirroring_learned():
    """A stub arm that silently reused the learned scorer would put a fake
    'independent supervision agreed' row into the ablation."""
    oracle, ps = _arm_pool()
    isb = ISB(oracle, scorer=SalienceScorer(oracle))
    with pytest.raises(NotImplementedError, match="mining.py"):
        isb.run_arm("fam", ps, "analyst")


def test_random_k_is_matched_on_budgeted_count_not_total():
    """learned's total includes budget-exempt hashes; matching on the total
    would hand random_kthose slots as ranked-type picks instead."""
    h = Candidate(value="c" * 64, ctype=CType.HASH_SHA256, source="t")
    oracle, ps = _arm_pool()
    ps = ps + [pooled(h, 10, 10)]
    out = ISB(oracle).run_ladder("fam", ps, arms=("learned", "random_k"))
    assert out["random_k"].stats["n_budgeted"] == out["learned"].stats["n_budgeted"]


def test_random_k_also_receives_the_free_hash_terms():
    h = Candidate(value="d" * 64, ctype=CType.HASH_SHA256, source="t")
    oracle, ps = _arm_pool()
    ps = ps + [pooled(h, 10, 10)]
    out = ISB(oracle).run_ladder("fam", ps, arms=("learned", "random_k"))
    assert h in out["random_k"].selected and h in out["learned"].selected


def test_every_arm_returns_only_expressible_candidates():
    oracle, ps = _arm_pool()
    ps = ps + [pooled(C("ab"), 9, 10)]        # too short to express
    isb = ISB(oracle)
    for arm in ("all", "lint", "prevalence_k", "learned"):
        assert all(c.norm != "ab" for c in isb.run_arm("fam", ps, arm).selected)


# ------------------------------------------------------------ span index

def test_span_key_normalizes_spacing_and_case():
    from YaraGen.StaticFeatures.spanindex import canonical_span_key
    assert canonical_span_key("21B8  01") == canonical_span_key("21b8 01")


def test_build_span_df_finds_and_misses_correctly(tmp_path):
    from YaraGen.StaticFeatures.spanindex import build_span_df
    present = bytes.fromhex("21B8014CCD215468")
    (tmp_path / "a.bin").write_bytes(b"padding" + present + b"tail")
    (tmp_path / "b.bin").write_bytes(b"nothing to see here at all")
    index, meta = build_span_df(
        ["21 B8 01 4C CD 21 54 68", "DE AD BE EF DE AD BE EF"],
        [str(tmp_path / "a.bin"), str(tmp_path / "b.bin")])
    assert index.count("21 B8 01 4C CD 21 54 68") == 1
    assert index.count("DE AD BE EF DE AD BE EF") == 0
    assert index.n_docs == 2
    assert meta["n_spans_absent"] == 1


def test_build_span_df_counts_a_file_once_per_span(tmp_path):
    from YaraGen.StaticFeatures.spanindex import build_span_df
    needle = bytes.fromhex("DEADBEEFDEADBEEF")
    (tmp_path / "a.bin").write_bytes(needle + b"gap" + needle + b"gap" + needle)
    index, _ = build_span_df(["DE AD BE EF DE AD BE EF"],
                             [str(tmp_path / "a.bin")])
    assert index.count("DE AD BE EF DE AD BE EF") == 1     # documents, not hits


def test_build_span_df_reports_rejected_spans_rather_than_scoring_them(tmp_path):
    from YaraGen.StaticFeatures.spanindex import build_span_df
    (tmp_path / "a.bin").write_bytes(b"x" * 32)
    _index, meta = build_span_df(["?? ??"], [str(tmp_path / "a.bin")])
    assert meta["n_rejected"] == 1
    assert meta["n_spans"] == 0


def test_build_span_df_handles_unreadable_files(tmp_path):
    from YaraGen.StaticFeatures.spanindex import build_span_df
    (tmp_path / "a.bin").write_bytes(bytes.fromhex("DEADBEEFDEADBEEF"))
    index, meta = build_span_df(
        ["DE AD BE EF DE AD BE EF"],
        [str(tmp_path / "a.bin"), str(tmp_path / "missing.bin")])
    assert meta["n_unreadable"] == 1
    assert index.n_docs == 1


def test_span_index_round_trips_through_disk(tmp_path):
    from YaraGen.StaticFeatures.spanindex import (
        build_span_df, load_span_df, save_span_df)
    (tmp_path / "a.bin").write_bytes(bytes.fromhex("DEADBEEFDEADBEEF"))
    index, meta = build_span_df(["DE AD BE EF DE AD BE EF"],
                                [str(tmp_path / "a.bin")])
    paths = save_span_df(index, meta, str(tmp_path))
    again = load_span_df(paths["index"])
    assert again.n_docs == index.n_docs
    assert again.count("DE AD BE EF DE AD BE EF") == 1


def test_span_index_plugs_into_the_oracle(tmp_path):
    """The whole point: an index built by the scanner must score a HEX_SPAN."""
    from YaraGen.StaticFeatures.spanindex import build_span_df
    (tmp_path / "a.bin").write_bytes(bytes.fromhex("DEADBEEFDEADBEEF"))
    index, _ = build_span_df(["DE AD BE EF DE AD BE EF"],
                             [str(tmp_path / "a.bin")])
    oracle = GoodwareOracle(spans=index)
    v = oracle.verdict(HEX("DE AD BE EF DE AD BE EF"))
    assert v.index == "spans" and v.count == 1 and v.absent is False


def test_spanindex_does_not_import_yaramod_or_torch():
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r);"
         "import YaraGen.StaticFeatures.spanindex;"
         "bad=[m for m in ('yaramod','tensorflow','evaluate','torch') "
         "if m in sys.modules]; print(','.join(bad))" % root],
        capture_output=True, text=True)
    assert out.stdout.strip() == "", out.stdout


# ------------------------------------------- hex-decoded runtime boilerplate

def _hexof(text: str) -> str:
    return " ".join(f"{b:02X}" for b in text.encode())


def test_hex_span_decoding_catches_runtime_fragments():
    """Attributed spans arrive cut mid-token (``fer.nVolumeNa``), so the needle
    is a fragment OF a known name -- matching runs in both directions."""
    from YaraGen.ISB.stoplist import Stoplist
    sl = Stoplist()
    for frag in ("fer\x00nVolumeNa", "ootPathName\x00lpVolumeNa", "\x00lpVolume",
                 "mNameBuffer\x00nFileSyst", "m\x00ReadByte\x00ToL"):
        cand = Candidate(value=_hexof(frag), ctype=CType.HEX_SPAN, source="c")
        assert sl.hits(cand), frag


def test_hex_span_decoding_keeps_family_signal():
    from YaraGen.ISB.stoplist import Stoplist
    sl = Stoplist()
    for keep in ("njRAT-Panel-2024", "VirtualAllocEx", "System.Net.Sockets",
                 "CreateRemoteThread", "keylogger.dat", "Bitcoin wallet"):
        cand = Candidate(value=_hexof(keep), ctype=CType.HEX_SPAN, source="c")
        assert sl.hits(cand) is None, keep


def test_short_decoded_fragments_are_not_matched():
    """At a 6-char floor, ``system`` is a substring of ``lpfilesystemnamebuffer``
    and System.Net.Sockets would die. The floor is 8 for that reason."""
    from YaraGen.ISB.stoplist import MIN_DECODED_FRAGMENT, Stoplist
    assert MIN_DECODED_FRAGMENT >= 8
    cand = Candidate(value=_hexof("system"), ctype=CType.HEX_SPAN, source="c")
    assert Stoplist().hits(cand) is None


def test_rich_header_span_is_rejected():
    from YaraGen.ISB.stoplist import Stoplist
    cand = Candidate(value=_hexof("\x00V`\x00\x00Pf\x00Rich"),
                     ctype=CType.HEX_SPAN, source="c")
    assert Stoplist().hits(cand) == "hex_rich_header"


def test_trivial_hex_still_wins_over_decoding():
    from YaraGen.ISB.stoplist import Stoplist
    cand = Candidate(value="00 00 00 00 00 00 00 00", ctype=CType.HEX_SPAN,
                     source="c")
    assert str(Stoplist().hits(cand)).startswith("trivial_hex")


# --------------------------------------------------------- scorer evaluation

def _grouped_table(n_families=8):
    rows, labels, groups = [], [], []
    for f in range(n_families):
        for i in range(60):
            pos = i % 3 == 0
            rows.append({"prevalence": 0.9 if pos else 0.1,
                         "goodware_rate": 0.0 if pos else 0.4,
                         "length": 20.0})
            labels.append(1 if pos else 0)
            groups.append(f"fam{f}")
    return rows, labels, groups


def test_fit_reports_pr_auc_on_a_family_grouped_holdout():
    rows, labels, groups = _grouped_table()
    s = SalienceScorer(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)),
                       SalienceConfig(min_positives=10, n_estimators=20))
    summary = s.fit(rows, labels, groups=groups)
    ev = summary["evaluation"]
    assert 0.0 <= ev["pr_auc"] <= 1.0
    assert "pr_auc_prevalence_baseline" in ev
    assert ev["held_out_families"]


def test_holdout_families_are_excluded_from_the_fit():
    rows, labels, groups = _grouped_table()
    s = SalienceScorer(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)),
                       SalienceConfig(min_positives=10, n_estimators=20))
    summary = s.fit(rows, labels, groups=groups)
    held = set(summary["evaluation"]["held_out_families"])
    assert summary["n_rows"] == sum(1 for g in groups if g not in held)
    assert summary["n_rows"] < summary["n_rows_total"]


def test_too_few_families_skips_the_holdout_rather_than_faking_it():
    rows, labels, groups = _grouped_table(n_families=2)
    s = SalienceScorer(GoodwareOracle(strings=DFIndex(df={}, n_docs=10)),
                       SalienceConfig(min_positives=10, n_estimators=20))
    ev = s.fit(rows, labels, groups=groups)["evaluation"]
    assert "pr_auc" not in ev and "skipped" in ev


# ------------------------------------------------- negative subsampling

def _wide_family(name, n_pos=3, n_neg=400):
    """A family with many negatives and few positives (the real shape)."""
    cands = [C(f"PositiveMarkerValue{i}") for i in range(n_pos)]
    rare = [C(f"RareValue{i}") for i in range(n_neg)]
    samples = {f"s{j}": list(cands) for j in range(4)}
    samples["s0"] = list(cands) + rare          # support 1 -> negative
    return family_set(name, samples), cands, rare


def test_negatives_are_capped_per_family():
    fcs, cands, rare = _wide_family("fam")
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=100))
    pool = {"fam": [pooled(c, 4, 4) for c in cands]
                   + [pooled(c, 1, 4) for c in rare]}
    table = build_training_table(
        [fcs], pool, oracle,
        SupervisionConfig(negative_cap_ratio=10), allowed_families=["fam"])
    assert table["summary"]["n_positive"] == 3
    assert table["summary"]["n_negative"] == 30           # 10 x 3
    assert table["per_family"]["fam"]["n_negatives_available"] == 400


def test_negative_subsampling_records_the_rate_it_used():
    fcs, cands, rare = _wide_family("fam")
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=100))
    pool = {"fam": [pooled(c, 4, 4) for c in cands]
                   + [pooled(c, 1, 4) for c in rare]}
    table = build_training_table(
        [fcs], pool, oracle, SupervisionConfig(negative_cap_ratio=10),
        allowed_families=["fam"])
    assert table["per_family"]["fam"]["negatives_kept_frac"] == pytest.approx(30 / 400)


def test_holdout_families_keep_every_negative():
    """A subsampled holdout would report an optimistic precision."""
    fcs, cands, rare = _wide_family("fam")
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=100))
    pool = {"fam": [pooled(c, 4, 4) for c in cands]
                   + [pooled(c, 1, 4) for c in rare]}
    table = build_training_table(
        [fcs], pool, oracle,
        SupervisionConfig(negative_cap_ratio=10,
                          full_negative_families=frozenset({"fam"})),
        allowed_families=["fam"])
    assert table["summary"]["n_negative"] == 400
    assert table["per_family"]["fam"]["negatives_kept_frac"] == 1.0


def test_subsampling_is_seeded():
    def build():
        fcs, cands, rare = _wide_family("fam")
        oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=100))
        pool = {"fam": [pooled(c, 4, 4) for c in cands]
                       + [pooled(c, 1, 4) for c in rare]}
        return build_training_table(
            [fcs], pool, oracle, SupervisionConfig(negative_cap_ratio=10),
            allowed_families=["fam"])["rows"]
    assert build() == build()


def test_pick_holdout_is_deterministic_and_proportional():
    fams = [f"fam{i}" for i in range(12)]
    a = SalienceScorer.pick_holdout(fams)
    assert a == SalienceScorer.pick_holdout(fams)
    assert len(a) == 3 and set(a) <= set(fams)


def test_pick_holdout_declines_when_families_are_too_few():
    assert SalienceScorer.pick_holdout(["a", "b"]) == []


# ------------------------------------ supervision must not be a tautology

def test_gen_side_supervision_is_a_function_of_its_own_features():
    """Pinning the DEFECT, so nobody reintroduces it. With support scored on the
    same samples the features come from, label == (prevalence >= m/n AND
    goodware_rate == 0) exactly -- measured agreement 1.000000 on the real
    F_train table, and the scorer hit PR-AUC 1.0 by rediscovering it."""
    cands = [C(f"MarkerValueNumber{i}") for i in range(10)]
    samples = {f"s{j}": cands[:j + 1] for j in range(10)}
    fcs = family_set("fam", samples)
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=500))
    labels = label_family(fcs, oracle, SupervisionConfig(), m=5)
    assert labels.support_side == "gen"
    for key in labels.positives | labels.negatives:
        prevalence = fcs.support(key) / fcs.n_samples
        predicted = prevalence >= 0.5          # m/n = 5/10
        assert predicted == (key in labels.positives)


def test_held_side_supervision_breaks_the_tautology():
    """Same gen prevalence, opposite label -- so no function of gen features can
    reproduce it, which is what makes the scorer's job real."""
    persists = C("PersistsIntoHeldHalf")
    vanishes = C("VanishesAfterGenHalf")
    gen = family_set("fam", {f"s{j}": [persists, vanishes] for j in range(4)})
    held = family_set("fam", {f"h{j}": [persists] for j in range(4)})
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=500))
    labels = label_family(gen, oracle, SupervisionConfig(), m=2, held=held)

    assert labels.support_side == "held"
    assert gen.support(persists.key()) == gen.support(vanishes.key())   # identical features
    assert persists.key() in labels.positives
    assert vanishes.key() in labels.negatives


def test_held_supervision_counts_m_against_the_held_population():
    persists = C("PersistsIntoHeldHalf")
    gen = family_set("fam", {f"s{j}": [persists] for j in range(20)})
    held = family_set("fam", {f"h{j}": [persists] for j in range(6)})
    labels = label_family(gen, GoodwareOracle(strings=DFIndex(df={}, n_docs=9)),
                          held=held)
    assert labels.n_samples == 6
    assert labels.m == FamilyCandidateSet.default_m(6)


def test_training_table_threads_held_sets_through():
    persists, vanishes = C("PersistsIntoHeldHalf"), C("VanishesAfterGenHalf")
    gen = family_set("fam", {f"s{j}": [persists, vanishes] for j in range(4)})
    held = family_set("fam", {f"h{j}": [persists] for j in range(4)})
    oracle = GoodwareOracle(strings=DFIndex(df={}, n_docs=500))
    pool = {"fam": [pooled(persists, 4, 4), pooled(vanishes, 4, 4)]}
    table = build_training_table([gen], pool, oracle, allowed_families=["fam"],
                                 held_sets={"fam": held})
    assert table["summary"]["support_side"] == "held"
    assert table["summary"]["n_positive"] == 1
    assert table["summary"]["n_negative"] == 1


# ------------------------------------------------- analyst mining (PU arm)

RULE = '''
rule rule_name : SCRIPT {
  strings:
    $a = "UniqueAnalystMarkerString"
    $b = "short"
    $c = { 4D 5A 90 00 ?? ?? 03 00 }
    $d = { ?? ?? ?? ?? }
  condition: any of them
}
'''


def test_extract_rule_terms_keeps_substantive_terms_only():
    from YaraGen.ISB.mining import extract_rule_terms
    terms = extract_rule_terms(RULE)
    assert "uniqueanalystmarkerstring" in terms["strings"]
    assert "short" not in terms["strings"]                 # below MIN_TERM_LEN
    assert "4d 5a 90 00 ?? ?? 03 00" in terms["hex"]
    assert "?? ?? ?? ??" not in terms["hex"]               # no fixed bytes


def test_extract_rule_terms_never_raises_on_garbage():
    from YaraGen.ISB.mining import extract_rule_terms
    for junk in ("", "rule {{{ unterminated \"", None, "strings: $a = "):
        assert extract_rule_terms(junk) == {"strings": set(), "hex": set()} \
            or isinstance(extract_rule_terms(junk), dict)


def test_analyst_index_endorsement_is_casefolded():
    from YaraGen.ISB.mining import AnalystIndex
    idx = AnalystIndex(df={"uniqueanalystmarkerstring": 4}, n_rules=10)
    assert idx.endorses(C("UniqueAnalystMarkerString"))
    assert not idx.endorses(C("SomethingElseEntirely"))


def test_analyst_index_respects_min_rules():
    from YaraGen.ISB.mining import AnalystIndex
    idx = AnalystIndex(df={"marker": 1}, n_rules=10)
    cand = C("Marker")
    assert idx.endorses(cand, min_rules=1)
    assert not idx.endorses(cand, min_rules=2)


def test_hex_endorsement_normalises_spacing():
    from YaraGen.ISB.mining import AnalystIndex
    idx = AnalystIndex(df={"4d 5a 90 00": 3}, n_rules=5)
    assert idx.endorses(HEX("4D 5A 90 00"))


def test_pu_scorer_falls_back_to_raw_endorsement_when_positives_are_few():
    from YaraGen.ISB.mining import AnalystIndex, PUBaggingScorer
    idx = AnalystIndex(df={"endorsedmarkervalue": 3}, n_rules=9)
    pu = PUBaggingScorer(idx, min_positives=30)
    pool = [pooled(C("EndorsedMarkerValue")), pooled(C("NotEndorsedValue"))]
    summary = pu.fit([dict(p.features()) for p in pool], pu.positives(pool))
    assert summary["fitted"] is False
    assert pu.score(pool) == [1.0, 0.0]


def test_pu_bagging_fits_and_averages_over_bags():
    from YaraGen.ISB.mining import AnalystIndex, PUBaggingScorer
    endorsed = {f"endorsedvalue{i}": 2 for i in range(40)}
    idx = AnalystIndex(df=endorsed, n_rules=100)
    pool = [pooled(C(f"EndorsedValue{i}"), 9, 10) for i in range(40)] + \
           [pooled(C(f"UnlabeledValue{i}"), 1, 10) for i in range(200)]
    pu = PUBaggingScorer(idx, min_positives=10, n_bags=4)
    summary = pu.fit([dict(p.features()) for p in pool], pu.positives(pool))
    assert summary["fitted"] is True and summary["n_bags"] == 4
    scores = pu.score(pool)
    assert len(scores) == len(pool) and all(0.0 <= s <= 1.0 for s in scores)


def test_pu_bagging_is_seeded():
    from YaraGen.ISB.mining import AnalystIndex, PUBaggingScorer
    idx = AnalystIndex(df={f"endorsedvalue{i}": 2 for i in range(40)}, n_rules=100)
    pool = [pooled(C(f"EndorsedValue{i}"), 9, 10) for i in range(40)] + \
           [pooled(C(f"UnlabeledValue{i}"), 1, 10) for i in range(200)]

    def run():
        pu = PUBaggingScorer(idx, min_positives=10, n_bags=3)
        pu.fit([dict(p.features()) for p in pool], pu.positives(pool))
        return pu.score(pool)
    assert run() == run()


def test_analyst_arm_runs_once_a_scorer_is_supplied():
    from YaraGen.ISB.mining import AnalystIndex, PUBaggingScorer
    oracle, ps = _arm_pool()
    idx = AnalystIndex(df={"uniquemarkerstringone": 5}, n_rules=50)
    isb = ISB(oracle, analyst=PUBaggingScorer(idx))
    sel = isb.run_arm("fam", ps, "analyst")
    assert sel.arm == "analyst" and sel.stats["budgeted"] is True
    assert isb.analyst_available is True


def test_analyst_arm_still_refuses_without_a_scorer():
    oracle, ps = _arm_pool()
    isb = ISB(oracle, scorer=SalienceScorer(oracle))
    assert isb.analyst_available is False
    with pytest.raises(NotImplementedError, match="PUBaggingScorer"):
        isb.run_arm("fam", ps, "analyst")


def test_ladder_includes_analyst_when_available():
    from YaraGen.ISB.mining import AnalystIndex, PUBaggingScorer
    oracle, ps = _arm_pool()
    idx = AnalystIndex(df={"uniquemarkerstringone": 5}, n_rules=50)
    out = ISB(oracle, analyst=PUBaggingScorer(idx)).run_ladder(
        "fam", ps, arms=ARMS, oracle_hits=lambda c: True)
    assert set(out) == set(ARMS)


def test_marshalling_names_are_stoplisted_as_plain_strings_too():
    """The .NET metadata naming a P/Invoke parameter is an extracted string in
    its own right, not only a fragment inside an attributed byte span.
    `lpFileSystemFlags` reached a BinaryToRule smoke rule because this list was
    consulted only for hex."""
    from YaraGen.ISB.stoplist import Stoplist
    sl = Stoplist()
    for value in ("lpFileSystemFlags", "lpVolumeNameBuffer",
                  "lpVolumeSerialNumber", "nFileSystemNameBuffer"):
        assert sl.hits(C(value)), value


def test_marshalling_stoplist_keeps_the_api_being_called():
    """`GetVolumeInformationW` is behaviour -- what the sample DOES. The
    lp*/n* parameter names are the compiler writing out a signature."""
    from YaraGen.ISB.stoplist import Stoplist
    sl = Stoplist()
    for value in ("GetVolumeInformationW", "CreateRemoteThread",
                  "System.Net.Sockets", "njRAT-Panel-2024",
                  "add_SessionEnding", "keylogger.dat"):
        assert sl.hits(C(value)) is None, value

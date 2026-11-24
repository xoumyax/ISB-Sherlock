"""ISB — Intelligent Selection Block, and the shared candidate core.

M0 scope (see ``finalExperimets/e2e-experiment/IMPLEMENTATION_PLAN.md``): only
the *provenance-blind* pieces both experiments share.

* :mod:`candidate` — the frozen ``Candidate`` IR and value normalization.
* :mod:`grammar` — YARA expressibility filter and rendering.
* :mod:`pooling` — family-level pooling, support statistics, scorer features.
* :mod:`stoplist` — the curated always-active hygiene list.

M3 adds ``goodware`` (type-routed genericity lookup), ``supervision``
(direct-empirical labels), ``salience`` (ISB-A scorer), ``budget``, ``condition``
(ISB-B) and ``isb`` (the arm ladder). Nothing here knows whether a candidate came from a threat report or a
byte-CNN, which is what lets both experiments share one pipeline.

Import-order note: this package never imports ``yaramod`` or anything that
pulls HuggingFace ``evaluate``/TensorFlow, so it is safe to import from
anywhere.
"""

from .candidate import (
    CASEFOLD_TYPES,
    DEFANGABLE_TYPES,
    EXP1_TYPES,
    EXP2_TYPES,
    HASH_TYPES,
    HEX_TYPES,
    TYPE_ALIASES,
    TYPE_SPACE,
    Candidate,
    CType,
    canonical_ctype,
    dedupe,
    normalize_value,
    refang,
    render_value,
    repair_split_hash,
)
from .grammar import (
    YARA_KEYWORDS,
    Expressibility,
    GrammarConfig,
    RenderKind,
    escape_text,
    expressible,
    filter_expressible,
    render_kind,
    render_module_term,
    render_string,
    required_modules,
    safe_identifier,
    sanitize_rule_name,
    validate_hex_body,
    validate_modifiers,
)
from .pooling import (
    DFIndex,
    FamilyCandidateSet,
    PooledCandidate,
    build_xfam_index,
    pool_families,
    value_entropy,
)
from .budget import BudgetConfig, apply_budget, type_cover
from .condition import ConditionBrain, ConditionConfig, ConditionPlan
from .goodware import GoodwareOracle, GoodwareVerdict
from .isb import ARMS, ISB, ISBConfig, Selection
from .mining import (
    AnalystIndex,
    PUBaggingScorer,
    build_analyst_index,
    extract_rule_terms,
    load_analyst_index,
)
from .salience import PriorScorer, SalienceConfig, SalienceScorer
from .supervision import (
    FamilyLabels,
    SupervisionConfig,
    build_training_table,
    label_family,
)
from .stoplist import (
    MAX_HEX_NULL_FRAC,
    MIN_HEX_DISTINCT_BYTES,
    Stoplist,
    trivial_hex_reason,
)

__all__ = [
    # candidate
    "Candidate", "CType", "TYPE_SPACE", "EXP1_TYPES", "EXP2_TYPES",
    "TYPE_ALIASES", "HASH_TYPES", "HEX_TYPES", "CASEFOLD_TYPES",
    "DEFANGABLE_TYPES", "canonical_ctype", "normalize_value", "render_value",
    "refang", "repair_split_hash", "dedupe",
    # grammar
    "Expressibility", "GrammarConfig", "RenderKind", "YARA_KEYWORDS",
    "expressible", "filter_expressible", "render_kind", "render_string",
    "render_module_term", "required_modules", "escape_text",
    "safe_identifier", "sanitize_rule_name", "validate_modifiers",
    "validate_hex_body",
    # pooling
    "DFIndex", "FamilyCandidateSet", "PooledCandidate", "build_xfam_index",
    "pool_families", "value_entropy",
    # goodware / supervision / selection (M3)
    "GoodwareOracle", "GoodwareVerdict",
    "SupervisionConfig", "FamilyLabels", "label_family", "build_training_table",
    "SalienceScorer", "SalienceConfig", "PriorScorer",
    "BudgetConfig", "type_cover", "apply_budget",
    "ConditionBrain", "ConditionConfig", "ConditionPlan",
    "ISB", "ISBConfig", "Selection", "ARMS",
    "AnalystIndex", "PUBaggingScorer", "build_analyst_index",
    "extract_rule_terms", "load_analyst_index",
    # stoplist
    "Stoplist", "trivial_hex_reason", "MIN_HEX_DISTINCT_BYTES",
    "MAX_HEX_NULL_FRAC",
]

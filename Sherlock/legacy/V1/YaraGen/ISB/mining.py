"""Analyst-rule mining: the secondary, independent supervision arm (§6).

The primary supervision (:mod:`supervision`) is direct-empirical -- it looks at
our corpus and asks whether a candidate persists into a family's held half. This
arm asks a completely different question: **has a human analyst ever put this
value in a detection rule?** Two independent signals disagreeing is informative;
two views of the same corpus agreeing is not, which is the whole point of having
a secondary arm.

**Family matching is not possible with the corpus we have, and this arm is
family-agnostic as a result.** ``EXP2_DESIGN §6`` specifies "rules matched to
families by normalized name". Every rule in ``YaraGen/Data/Crawled/`` has had its
name replaced with the literal ``rule_name`` (measured 2026-08-20: 1994/1994
rules across six repos, one distinct name, three tags total) -- the crawl
stripped them, almost certainly so the generation task could not memorise them.
Recovering them means re-crawling 59 repositories.

So the endorsement this arm provides is:

    "this exact value appears in a human-written YARA rule somewhere"

not "an analyst says this identifies family F". That is weaker, and it must be
written up as such -- but it is still a real, independent endorsement, and it is
arguably *more* robust than name matching, which would have introduced its own
false pairings ("njrat" matching a rule about a njRAT-dropping loader).

**Why PU lives only here.** The primary arm has real negatives: a candidate that
demonstrably fails to persist into the held half is a true negative. Here there
are none. A value's absence from our 59 repositories means nothing -- no analyst
has written a public rule about most of the malware in the world. Positives are
reliable, unlabeled is genuinely unlabeled, so PU-bagging is the correct
estimator and it is confined to this module.

No ``yaramod``: this package must stay importable from anywhere, and parsing
crawled rules is a term-extraction job, not a semantic one. Extraction is
regex-based and deliberately tolerant -- a rule we cannot parse contributes
nothing rather than aborting a 59-repository build.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from .candidate import Candidate
from .pooling import PooledCandidate

__all__ = [
    "AnalystIndex",
    "extract_rule_terms",
    "build_analyst_index",
    "save_analyst_index",
    "load_analyst_index",
    "PUBaggingScorer",
]

#: ``$id = "literal" modifiers`` -- the escaped-quote body is non-greedy so a
#: rule with several strings on one line does not collapse into one term.
_STR_RE = re.compile(r'\$[\w]*\s*=\s*"((?:[^"\\]|\\.)*)"')
#: ``$id = { 4D 5A ?? }`` -- hex bodies, wildcards and jumps included.
_HEX_RE = re.compile(r'\$[\w]*\s*=\s*\{([0-9A-Fa-f?\s\[\]\-~()|]+)\}')

#: Values too short or too generic to be evidence of anything. A rule containing
#: "MZ" endorses nothing.
MIN_TERM_LEN = 6


def _unescape(raw: str) -> str:
    return (raw.replace('\\"', '"').replace("\\\\", "\\")
            .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t"))


def canonical_term(value: str, is_hex: bool = False) -> str:
    """Index key for a mined term.

    Case-folded to match ``DFIndex``/``GoodwareOracle`` convention: an analyst
    writing ``CreateRemoteThread`` and an extractor reporting
    ``createremotethread`` are the same endorsement.
    """
    if is_hex:
        return " ".join(value.split()).lower()
    return value.strip().lower()


def extract_rule_terms(yara_text: str) -> dict[str, set[str]]:
    """Literal string and hex terms from one rule's source.

    Returns ``{"strings": {...}, "hex": {...}}``. Regexes rather than a parser
    on purpose (see module docstring); malformed input yields fewer terms, never
    an exception.
    """
    strings: set[str] = set()
    hexes: set[str] = set()
    if not yara_text:
        return {"strings": strings, "hex": hexes}

    for m in _STR_RE.finditer(yara_text):
        val = _unescape(m.group(1))
        if len(val) >= MIN_TERM_LEN:
            strings.add(canonical_term(val))
    for m in _HEX_RE.finditer(yara_text):
        body = canonical_term(m.group(1), is_hex=True)
        # Count fixed bytes only: "?? ?? ?? ??" endorses nothing.
        fixed = [t for t in body.split() if len(t) == 2 and "?" not in t]
        if len(fixed) >= 4:
            hexes.add(body)
    return {"strings": strings, "hex": hexes}


@dataclass
class AnalystIndex:
    """How many crawled rules carry each term.

    ``df`` counts *rules*, not repositories: a value used by twenty independent
    rules is better evidence than one used twice in the same file, and rule-level
    counting is the closest we get to that without repository provenance.
    """

    df: Mapping[str, int] = field(default_factory=dict)
    n_rules: int = 0
    n_sources: int = 0

    def count(self, value: str) -> int:
        return int(self.df.get(value.strip().lower(), 0))

    def endorses(self, cand: Candidate, min_rules: int = 1) -> bool:
        key = (canonical_term(cand.value, is_hex=True) if cand.is_hex
               else canonical_term(cand.value))
        return self.count(key) >= min_rules

    def __contains__(self, value: str) -> bool:
        return self.count(value) > 0

    def summary(self) -> dict[str, Any]:
        return {"n_terms": len(self.df), "n_rules": self.n_rules,
                "n_sources": self.n_sources}


def build_analyst_index(
    crawled_dir: str,
    limit_files: int = 0,
    progress: Callable[[str], None] | None = None,
) -> tuple[AnalystIndex, dict[str, Any]]:
    """Mine every crawled repository pickle into one term index.

    Each pickle is a DataFrame whose ``translation`` column holds ``{"yara":
    source, "en": ...}``. A file that fails to load is recorded and skipped: the
    corpus is 59 heterogeneous repository dumps and one bad pickle must not cost
    the other 58.
    """
    import pickle
    from collections import Counter

    log = progress or (lambda _m: None)
    paths = sorted(glob.glob(os.path.join(crawled_dir, "*.pkl")))
    if limit_files:
        paths = paths[:limit_files]

    df: Counter[str] = Counter()
    n_rules = 0
    failed: dict[str, str] = {}
    per_source: dict[str, int] = {}

    for path in paths:
        name = os.path.basename(path)
        try:
            with open(path, "rb") as fh:
                frame = pickle.load(fh)
            rows = frame["translation"]
        except Exception as exc:                       # noqa: BLE001
            failed[name] = f"{type(exc).__name__}: {exc}"[:120]
            continue
        before = n_rules
        for entry in rows:
            text = (entry or {}).get("yara") if isinstance(entry, dict) else None
            if not text:
                continue
            n_rules += 1
            terms = extract_rule_terms(text)
            for key in terms["strings"] | terms["hex"]:
                df[key] += 1
        per_source[name] = n_rules - before
        log(f"[mining] {name}: {per_source[name]} rules, {len(df)} terms so far")

    index = AnalystIndex(df=dict(df), n_rules=n_rules, n_sources=len(per_source))
    meta = {
        "n_terms": len(df), "n_rules": n_rules,
        "n_sources": len(per_source), "per_source": per_source,
        "failed": failed, "min_term_len": MIN_TERM_LEN,
        "family_matched": False,
        "note": ("crawled rule names are anonymised to 'rule_name', so this "
                 "index is family-agnostic analyst endorsement, not "
                 "family-matched supervision (EXP2_DESIGN §6 deviation)"),
    }
    log(f"[mining] done: {n_rules} rules, {len(df)} terms, "
        f"{len(failed)} unreadable files")
    return index, meta


def save_analyst_index(index: AnalystIndex, meta: Mapping[str, Any],
                       out_dir: str, stem: str = "analyst_terms") -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    idx = os.path.join(out_dir, f"{stem}.json")
    mp = os.path.join(out_dir, f"{stem}.meta.json")
    with open(idx, "w") as fh:
        json.dump({"n_rules": index.n_rules, "n_sources": index.n_sources,
                   "df": index.df}, fh)
    with open(mp, "w") as fh:
        json.dump(dict(meta), fh, indent=2)
    return {"index": idx, "meta": mp}


def load_analyst_index(path: str) -> AnalystIndex:
    with open(path) as fh:
        blob = json.load(fh)
    return AnalystIndex(df=blob["df"], n_rules=int(blob.get("n_rules", 0)),
                        n_sources=int(blob.get("n_sources", 0)))


class PUBaggingScorer:
    """Positive-Unlabeled bagging over analyst-endorsed positives.

    Each bag draws a random subsample of the unlabeled pool to stand in as
    negatives and fits one estimator; scores are averaged over bags. That is the
    standard PU-bagging construction, and the averaging is what stops any single
    unlucky draw -- one that happened to sample mostly true positives as
    negatives -- from dominating.

    Falls back to raw endorsement (a 1/0 score) when there are too few positives
    to fit anything, rather than returning a model fitted on nothing.
    """

    name = "analyst"

    def __init__(
        self,
        index: AnalystIndex,
        min_rules: int = 1,
        n_bags: int = 10,
        seed: int = 20260809,
        min_positives: int = 30,
    ):
        self.index = index
        self.min_rules = min_rules
        self.n_bags = n_bags
        self.seed = seed
        self.min_positives = min_positives
        self.models: list[Any] = []
        self.feature_names: list[str] = []
        self.train_summary: dict[str, Any] = {}

    def positives(self, pooled: Sequence[PooledCandidate]) -> list[int]:
        """1 where an analyst rule carries the value, else 0 (unlabeled)."""
        return [1 if self.index.endorses(p.candidate, self.min_rules) else 0
                for p in pooled]

    def _matrix(self, rows: Sequence[Mapping[str, float]]):
        import numpy as np
        return np.asarray(
            [[float(r.get(k, 0.0)) for k in self.feature_names] for r in rows],
            dtype=float).reshape(len(rows), len(self.feature_names))

    def fit(
        self,
        rows: Sequence[Mapping[str, float]],
        labels: Sequence[int],
        feature_names: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        import random as _random

        self.feature_names = list(
            feature_names or (sorted(rows[0]) if rows else []))
        pos_idx = [i for i, v in enumerate(labels) if v == 1]
        unl_idx = [i for i, v in enumerate(labels) if v != 1]

        if len(pos_idx) < self.min_positives or not unl_idx:
            self.models = []
            self.train_summary = {
                "fitted": False, "reason": "insufficient_endorsed_positives",
                "n_positive": len(pos_idx), "n_unlabeled": len(unl_idx),
                "scorer": self.name,
            }
            return self.train_summary

        import lightgbm as lgb

        rng = _random.Random(self.seed)
        n_draw = min(len(unl_idx), max(len(pos_idx), 1))
        self.models = []
        for bag in range(self.n_bags):
            drawn = rng.sample(unl_idx, n_draw)
            idx = pos_idx + drawn
            y = [1] * len(pos_idx) + [0] * len(drawn)
            model = lgb.LGBMClassifier(
                n_estimators=100, learning_rate=0.05, num_leaves=31,
                random_state=self.seed + bag, verbose=-1)
            model.fit(self._matrix([rows[i] for i in idx]), y)
            self.models.append(model)

        self.train_summary = {
            "fitted": True, "n_bags": len(self.models),
            "n_positive": len(pos_idx), "n_unlabeled": len(unl_idx),
            "draw_per_bag": n_draw, "scorer": self.name,
            "feature_names": self.feature_names,
        }
        return self.train_summary

    def score(self, pooled: Sequence[PooledCandidate]) -> list[float]:
        if not pooled:
            return []
        if not self.models:
            return [float(v) for v in self.positives(pooled)]
        rows = [dict(p.features()) for p in pooled]
        mat = self._matrix(rows)
        total = [0.0] * len(pooled)
        for model in self.models:
            proba = model.predict_proba(mat)
            for i, pr in enumerate(proba):
                total[i] += float(pr[1])
        return [t / len(self.models) for t in total]

    def rank(self, pooled: Sequence[PooledCandidate]) -> list[PooledCandidate]:
        scored = list(zip(self.score(pooled), pooled))
        scored.sort(key=lambda sp: (-sp[0], sp[1].candidate.key()))
        return [p for _s, p in scored]

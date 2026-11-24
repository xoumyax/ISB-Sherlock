"""Scan harness: rules x corpora -> TPR, FP/1k, and explicit failures (§10, §8.4).

Ported from the pre-wipe §8.4 semantics, which exist because the obvious
implementation produces numbers that look fine and mean nothing:

* **Namespaced compile, one namespace per unit.** Rules from different arms
  share identifiers; compiled into one namespace they silently shadow each
  other and a whole arm scores zero for no visible reason.
* **One pass per corpus, not per rule.** Scanning 20k goodware files once per
  rule is the difference between minutes and days.
* **Cross-family matches are reported separately and never folded into FP.**
  A rule for family A firing on family B is a specificity finding; calling it a
  false positive would let a rule that detects *all malware* look precise.
* **Vault matches are not FP either.** The vault is malware. FP is a
  goodware-only metric (§10b).
* **Failures are outcomes, not silence.** ``compile_error``, ``timeout``,
  ``scan_error`` and ``missing_file`` each get a column. A rule that failed to
  compile and a rule that compiled and matched nothing both produce zero
  detections, and conflating them has cost this project a milestone before.

TPR is reported two ways because they answer different questions: **union-TPR**
(a family is detected if any of its rules fires -- the deployment question) and
**mean-per-unit** (how good is the average rule -- the modelling question).

SAFETY: ``yara.match`` reads bytes. Nothing here executes a sample, and the
corpus is live malware.
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

__all__ = ["ScanTarget", "RuleUnit", "DetectionConfig", "DetectionHarness"]

#: A ``strings:`` definition line. Used only to size a rule before compiling it.
_STRING_DEF = re.compile(r"^\s*\$[\w]*\s*=", re.M)


@dataclass(frozen=True)
class ScanTarget:
    """One file to scan, plus what it is."""

    sha256: str
    path: str
    #: "held" | "gen" | "goodware" | "vault"
    kind: str
    family: str | None = None
    source: str | None = None          # goodware source (Win8 = in-dist)


@dataclass
class RuleUnit:
    """One compiled-able rule and its provenance."""

    unit_id: str                       # namespace; must be unique per rule
    family: str
    arm: str
    source: str
    candidate_source: str = "static"   # static | classifier | union
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionConfig:
    #: Per-file yara timeout, seconds.
    match_timeout: int = 30
    #: Cap on goodware files scanned; for smokes only. 0 = all.
    goodware_cap: int = 0
    #: Report progress every N files (0 disables).
    log_every: int = 2000
    #: libyara refuses more than this many strings in one rule. Units over the
    #: limit are rejected WITHOUT calling yara.compile: validating a
    #: 412,000-string rule takes many minutes and can only ever end in the
    #: error we already know it will produce. Job 95875 spent >1.5h compiling
    #: 4.72M strings across 24 such units before this guard existed.
    max_strings_per_rule: int = 10_000


class DetectionHarness:
    """Compile once, scan once per corpus, attribute matches back to units."""

    def __init__(self, config: DetectionConfig | None = None,
                 progress: Callable[[str], None] | None = None):
        self.config = config or DetectionConfig()
        self.log = progress or (lambda _m: None)
        self.rules = None
        self.units: dict[str, RuleUnit] = {}
        self.compile_errors: dict[str, str] = {}

    # -- compile -------------------------------------------------------
    def compile(self, units: Sequence[RuleUnit]) -> dict[str, Any]:
        """Compile every unit into its own namespace.

        A unit that fails to compile is recorded and excluded; one bad rule must
        not take the other 200 with it, and its failure has to stay visible in
        the results rather than looking like a rule that matched nothing.
        """
        import yara

        sources: dict[str, str] = {}
        self.units = {}
        self.compile_errors = {}
        n_skipped = 0
        for unit in units:
            n_strings = unit.meta.get("n_strings")
            if n_strings is None:
                n_strings = len(_STRING_DEF.findall(unit.source))
            if n_strings > self.config.max_strings_per_rule:
                # Not an error we need yara to discover for us.
                self.compile_errors[unit.unit_id] = (
                    f"too_many_strings: {n_strings} > "
                    f"{self.config.max_strings_per_rule} (not compiled)")
                n_skipped += 1
                continue
            try:
                yara.compile(source=unit.source)      # validate in isolation
            except Exception as exc:                  # noqa: BLE001
                self.compile_errors[unit.unit_id] = f"{type(exc).__name__}: {exc}"[:200]
                continue
            sources[unit.unit_id] = unit.source
            self.units[unit.unit_id] = unit

        self.rules = yara.compile(sources=sources) if sources else None
        self.log(f"[detect] compiled {len(sources)}/{len(units)} units "
                 f"({len(self.compile_errors)} compile errors, "
                 f"{n_skipped} over the string limit -- not compiled)")
        return {"n_units": len(units), "n_compiled": len(sources),
                "n_over_string_limit": n_skipped,
                "compile_errors": dict(self.compile_errors)}

    # -- scan ----------------------------------------------------------
    def scan(self, targets: Sequence[ScanTarget]) -> dict[str, Any]:
        """One pass over ``targets``; returns per-unit and per-target outcomes."""
        if self.rules is None:
            return {"hits": {}, "outcomes": {}, "n_scanned": 0,
                    "failures": {"no_compiled_rules": len(targets)}}

        hits: dict[str, set[str]] = defaultdict(set)      # unit_id -> shas
        failures: dict[str, int] = defaultdict(int)
        n = 0
        t0 = time.time()
        for i, tgt in enumerate(targets):
            if not os.path.exists(tgt.path):
                failures["missing_file"] += 1
                continue
            try:
                matches = self.rules.match(
                    filepath=tgt.path, timeout=self.config.match_timeout)
            except Exception as exc:                      # noqa: BLE001
                name = type(exc).__name__.lower()
                failures["timeout" if "timeout" in name else "scan_error"] += 1
                continue
            n += 1
            for m in matches:
                # namespace == unit_id, which is why every unit gets its own.
                unit_id = getattr(m, "namespace", None)
                if unit_id in self.units:
                    hits[unit_id].add(tgt.sha256)
            if self.config.log_every and (i + 1) % self.config.log_every == 0:
                self.log(f"[detect] {i + 1}/{len(targets)} scanned")

        self.log(f"[detect] scanned {n}/{len(targets)} in {time.time() - t0:.0f}s")
        return {"hits": {k: sorted(v) for k, v in hits.items()},
                "n_scanned": n, "failures": dict(failures)}

    # -- scoring -------------------------------------------------------
    def score(
        self,
        held: Sequence[ScanTarget],
        goodware: Sequence[ScanTarget],
        gen: Sequence[ScanTarget] = (),
    ) -> dict[str, Any]:
        """Scan all three corpora and assemble the §10 metrics."""
        cfg = self.config
        good = list(goodware)
        if cfg.goodware_cap:
            good = good[: cfg.goodware_cap]

        held_res = self.scan(list(held))
        good_res = self.scan(good)
        gen_res = self.scan(list(gen)) if gen else {"hits": {}, "n_scanned": 0,
                                                    "failures": {}}

        held_by_family: dict[str, list[ScanTarget]] = defaultdict(list)
        for t in held:
            held_by_family[t.family or "?"].append(t)
        good_by_source: dict[str, int] = defaultdict(int)
        for t in good:
            good_by_source[t.source or "?"] += 1

        per_unit: dict[str, Any] = {}
        # union-TPR needs the set of held shas of the unit's OWN family that any
        # of its family's rules hit; accumulate per family as we go.
        union_hits: dict[str, set[str]] = defaultdict(set)

        for unit_id, unit in self.units.items():
            fam = unit.family
            fam_shas = {t.sha256 for t in held_by_family.get(fam, ())}
            hit = set(held_res["hits"].get(unit_id, ()))
            own = hit & fam_shas
            cross = hit - fam_shas          # other families' held samples
            benign = set(good_res["hits"].get(unit_id, ()))
            union_hits[fam] |= own

            benign_by_source: dict[str, int] = defaultdict(int)
            for t in good:
                if t.sha256 in benign:
                    benign_by_source[t.source or "?"] += 1

            per_unit[unit_id] = {
                "family": fam, "arm": unit.arm,
                "candidate_source": unit.candidate_source,
                "n_held_family": len(fam_shas),
                "tp": len(own), "fn": len(fam_shas) - len(own),
                "tpr": len(own) / len(fam_shas) if fam_shas else 0.0,
                "cross_match": len(cross),
                "gen_match": len(set(gen_res["hits"].get(unit_id, ()))),
                "benign_match": len(benign),
                "benign_by_source": dict(benign_by_source),
                "fp_per_1k": (1000.0 * len(benign) / len(good)) if good else 0.0,
            }

        families = sorted(held_by_family)
        union_tpr = {
            fam: (len(union_hits.get(fam, set())) / len(held_by_family[fam])
                  if held_by_family[fam] else 0.0)
            for fam in families
        }
        unit_tprs = [u["tpr"] for u in per_unit.values()]
        total_benign = len({sha for shas in good_res["hits"].values()
                            for sha in shas})

        return {
            "per_unit": per_unit,
            "union_tpr": union_tpr,
            "macro_union_tpr": (sum(union_tpr.values()) / len(union_tpr)
                                if union_tpr else 0.0),
            "mean_per_unit_tpr": (sum(unit_tprs) / len(unit_tprs)
                                  if unit_tprs else 0.0),
            "micro_tpr": (sum(u["tp"] for u in per_unit.values())
                          / max(1, sum(u["n_held_family"] for u in per_unit.values()))),
            # Goodware-only, by construction. Cross-family and vault matches are
            # reported elsewhere and never enter this number.
            "fp_per_1k_any_rule": (1000.0 * total_benign / len(good)) if good else 0.0,
            "n_goodware": len(good),
            "goodware_by_source": dict(good_by_source),
            "compile_errors": dict(self.compile_errors),
            "failures": {"held": held_res["failures"],
                         "goodware": good_res["failures"],
                         "gen": gen_res.get("failures", {})},
            "n_units": len(self.units),
        }

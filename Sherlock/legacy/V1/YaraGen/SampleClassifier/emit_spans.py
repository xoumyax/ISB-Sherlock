"""Classifier candidate source: attributed ``HEX_SPAN``s per family.

The static emitter (:mod:`YaraGen.StaticFeatures.emit`) is the ``static_only``
arm of the candidate-source ablation. This is the other half -- what the byte-CNN
*discovers* that no string extractor would surface -- and unioning the two is
what makes "what is discovery worth?" measurable end to end.

Attribution legality (EXP2_DESIGN §4): spans are attributed on a family's
**gen** samples with weights frozen from a model that never saw that family. Gen
samples are rule-building material, so reading them is legitimate; the ``held``
half is never touched here, and this module has no way to reach it -- callers
pass refs, and the driver builds them gen-only.

Output is per-sample so it can flow into ``FamilyCandidateSet.add_sample``
unchanged: pooling then computes prevalence over the same denominator as the
static candidates, and the two sources are genuinely comparable. The attributor
itself pools and gates by stability; here we re-expand a gated span onto the
samples that actually carry it, which is why the presence map comes back too.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..ISB.candidate import Candidate
from .attribute import Attributor, AttributionConfig
from .data import SampleRef

__all__ = ["SpanEmitConfig", "emit_family_spans"]


@dataclass(frozen=True)
class SpanEmitConfig:
    """Knobs for the classifier candidate source."""

    attribution: AttributionConfig = AttributionConfig()
    #: Cap on spans kept per family after gating, best-first. The budget only
    #: ever sees k=8, but the scorer trains on everything, so this is generous.
    max_spans_per_family: int = 512
    #: Read cap when re-expanding a span onto its carrying samples.
    presence_read_cap: int = 64 * 1024 * 1024


def _carriers(
    raw: bytes,
    refs: Sequence[SampleRef],
    read_cap: int,
    cache: dict[str, bytes],
) -> list[str]:
    """Which of ``refs`` contain these bytes. Static reads only -- SAFETY."""
    out: list[str] = []
    for ref in refs:
        data = cache.get(ref.sha256)
        if data is None:
            try:
                with open(ref.path, "rb") as fh:
                    data = fh.read(read_cap)
            except OSError:
                data = b""
            cache[ref.sha256] = data
        if data and raw in data:
            out.append(ref.sha256)
    return out


def emit_family_spans(
    attributor: Attributor,
    family: str,
    gen_refs: Sequence[SampleRef],
    config: SpanEmitConfig | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Attribute one family and return per-sample ``HEX_SPAN`` candidates.

    Returns ``{"per_sample": {sha: [Candidate, ...]}, "summary": {...}}``. The
    per-sample shape is the point: a span pooled at family level would carry no
    prevalence of its own, and prevalence is the feature the whole selection
    stage leans on.
    """
    config = config or SpanEmitConfig()
    log = progress or (lambda _m: None)

    cands = attributor.candidates_for_family(family, gen_refs)
    log(f"[spans] {family}: {len(cands)} gated spans from {len(gen_refs)} gen")
    cands = cands[: config.max_spans_per_family]

    per_sample: dict[str, list[Candidate]] = {r.sha256: [] for r in gen_refs}
    cache: dict[str, bytes] = {}
    n_placed = 0
    for cand in cands:
        try:
            raw = bytes.fromhex(cand.value.replace(" ", ""))
        except ValueError:
            continue
        if not raw:
            continue
        for sha in _carriers(raw, gen_refs, config.presence_read_cap, cache):
            per_sample[sha].append(cand)
            n_placed += 1

    return {
        "per_sample": per_sample,
        "summary": {
            "family": family,
            "n_gen": len(gen_refs),
            "n_spans_gated": len(cands),
            "n_placements": n_placed,
            "mean_carriers": round(n_placed / len(cands), 2) if cands else 0.0,
        },
    }

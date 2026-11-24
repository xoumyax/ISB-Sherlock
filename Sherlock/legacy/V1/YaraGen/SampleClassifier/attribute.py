"""Attribution: byte-CNN evidence -> ``HEX_SPAN`` candidates (EXP2_DESIGN §4).

Three stages, each narrowing the search:

1. **Which windows mattered** -- pooled window contribution from the forward pass
   (attention weights, or max-pool channel share). Cheap, and it comes from the
   network that actually made the prediction rather than a surrogate.
2. **Which bytes inside them** -- integrated gradients w.r.t. the byte embeddings
   within the top-K windows only. IG is expensive per window; running it after
   stage 1 makes it affordable.
3. **Which spans survive** -- contiguous high-saliency runs (min 8 bytes,
   gap-tolerant) become hex spans, then the **stability gate** keeps only spans
   present in >= m of the family's gen samples.

The stability gate is what separates this from a saliency picture. A span that is
salient in one sample is an artifact of that sample; a span salient in one sample
and *present* in many is a family trait. Without the gate every candidate would be
a per-sample curiosity, and the pre-wipe FP catastrophes are exactly what happens
when unstable candidates reach a rule.

Attribution runs against BOTH heads' logits and both scores travel with the
candidate, because ISB-A wants to weigh "this is malware-ish" separately from
"this is *this family*".

Legality: attribution runs on the target family's ``gen`` samples with weights
frozen from a model that never saw that family (EXP2_DESIGN §4). Gen samples are
rule-building material, so looking at them is legitimate; the ``held`` half is
never touched here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

import numpy as np
import torch

from ..ISB.candidate import Candidate, CType
from ..ISB.stoplist import trivial_hex_reason
from .data import SampleRef, WindowSampler
from .model import PAD_BYTE, WindowMalConv

__all__ = ["AttributionConfig", "AttributedSpan", "Attributor"]


@dataclass(frozen=True)
class AttributionConfig:
    #: Windows kept from stage 1 for the expensive IG pass.
    top_k_windows: int = 4
    #: Integrated-gradients interpolation steps.
    ig_steps: int = 16
    #: Saliency percentile within a window that counts as "high".
    saliency_percentile: float = 99.0
    #: Minimum contiguous high-saliency run, in bytes (EXP2_DESIGN §4).
    min_span_bytes: int = 8
    #: Maximum span length; longer runs are usually a whole salient region rather
    #: than a usable atom.
    max_span_bytes: int = 64
    #: Bytes of low saliency tolerated inside a run before it is cut.
    gap_tolerance: int = 2
    #: Spans emitted per sample, best-first.
    max_spans_per_sample: int = 32
    #: Stability gate: fraction of gen samples a span must appear in.
    stability_frac: float = 0.20
    stability_floor: int = 2
    #: Cap on bytes read per sample when checking span presence.
    presence_read_cap: int = 64 * 1024 * 1024
    #: Which family class attribution targets. ``argmax`` (default) keeps the
    #: score stationary between scorer training and deployment; ``true`` is for
    #: analysis of F_train families only and must not be used for the eval path.
    family_target: str = "argmax"


@dataclass
class AttributedSpan:
    """A candidate hex span plus the evidence that produced it."""

    hex_body: str
    raw: bytes
    file_offset: int
    sha256: str
    score_binary: float
    score_family: float
    support: int = 0
    n_gen: int = 0

    @property
    def prevalence(self) -> float:
        return self.support / self.n_gen if self.n_gen else 0.0

    def to_candidate(self, source: str = "classifier") -> Candidate:
        return Candidate(
            value=self.hex_body,
            ctype=CType.HEX_SPAN,
            source=source,
            attrs={
                "attribution_bin": self.score_binary,
                "attribution_fam": self.score_family,
                "support": self.support,
                "n_gen": self.n_gen,
                "example_sha256": self.sha256,
                "example_offset": self.file_offset,
            },
        )


def _hex_body(raw: bytes) -> str:
    return " ".join(f"{b:02X}" for b in raw)


class Attributor:
    """Runs attribution for one frozen model over a family's gen samples."""

    def __init__(
        self,
        model: WindowMalConv,
        sampler: WindowSampler,
        family_names: Sequence[str],
        config: AttributionConfig | None = None,
        device: str | torch.device = "cpu",
    ):
        self.model = model.eval()
        self.sampler = sampler
        self.family_names = list(family_names)
        self.config = config or AttributionConfig()
        self.device = torch.device(device)
        self.model.to(self.device)

    # -- stage 1 + 2 ---------------------------------------------------
    def _load_windows(
        self, ref: SampleRef, sections: Sequence[dict] | None
    ) -> tuple[torch.Tensor, list[int]]:
        """Returns ``(1, W, L)`` byte ids and the file offset of each window."""
        try:
            size = os.path.getsize(ref.path)
        except OSError:
            return torch.empty(0), []
        offsets = self.sampler.offsets(
            size, epoch=0, sha256=ref.sha256, sections=sections)

        arr = np.full((len(offsets), self.sampler.window_size), PAD_BYTE,
                      dtype=np.int64)
        kept: list[int] = []
        with open(ref.path, "rb") as fh:        # static read only -- SAFETY
            for i, off in enumerate(offsets):
                fh.seek(off)
                chunk = fh.read(self.sampler.window_size)
                if not chunk:
                    continue
                buf = np.frombuffer(chunk, dtype=np.uint8)
                arr[len(kept), : len(buf)] = buf
                kept.append(off)
        if not kept:
            return torch.empty(0), []
        return torch.from_numpy(arr[: len(kept)]).unsqueeze(0), kept

    @torch.no_grad()
    def _window_scores(self, windows: torch.Tensor) -> tuple[np.ndarray, dict]:
        mask = torch.ones(windows.shape[:2], dtype=torch.bool, device=self.device)
        out = self.model(windows.to(self.device), mask)
        return out["window_contribution"][0].float().cpu().numpy(), out

    def _integrated_gradients(
        self, window: torch.Tensor, target: str, class_index: int | None
    ) -> np.ndarray:
        """Per-byte saliency for one window, via integrated gradients.

        Baseline is the padding embedding -- the model's own "nothing here"
        representation, which is a more honest reference than an all-zero vector
        that corresponds to no real byte.
        """
        cfg = self.config
        # (L,) -> (batch=1, windows=1, L); the encoder is shaped for batches of
        # window sets, and IG runs one window at a time.
        window = window.to(self.device).reshape(1, 1, -1)
        mask = torch.ones((1, 1), dtype=torch.bool, device=self.device)

        with torch.no_grad():
            target_emb = self.model.embed(window)              # (1,1,L,E)
            baseline = self.model.embed(
                torch.full_like(window, PAD_BYTE))

        total = torch.zeros_like(target_emb)
        for step in range(cfg.ig_steps):
            alpha = (step + 0.5) / cfg.ig_steps
            point = (baseline + alpha * (target_emb - baseline)).detach()
            point.requires_grad_(True)
            window_emb = self.model.encode_from_embeddings(point)
            heads = self.model.heads_from_windows(window_emb, mask)
            logit = (heads["logit_binary"].sum() if target == "binary"
                     else heads["logits_family"][0, class_index])
            grad, = torch.autograd.grad(logit, point)
            total = total + grad.detach()

        ig = (total / cfg.ig_steps) * (target_emb - baseline)
        return ig.sum(dim=-1)[0, 0].abs().float().cpu().numpy()   # (L,)

    # -- stage 3 -------------------------------------------------------
    def _runs(self, saliency: np.ndarray, window_bytes: bytes) -> list[tuple[int, int]]:
        """Contiguous high-saliency runs, gap-tolerant, length-bounded."""
        cfg = self.config
        usable = min(len(saliency), len(window_bytes))
        if usable < cfg.min_span_bytes:
            return []
        sal = saliency[:usable]
        # Degenerate saliency yields no spans rather than a bogus whole-window
        # one. Two cases matter: flat saliency (nothing stood out), and a
        # percentile that lands on 0 -- common when saliency is sparse, and with
        # `sal >= 0` every byte would qualify as "hot".
        if float(sal.max()) <= 0.0 or float(sal.min()) == float(sal.max()):
            return []
        threshold = max(float(np.percentile(sal, cfg.saliency_percentile)),
                        float(np.nextafter(0.0, 1.0)))
        hot = sal >= threshold

        runs: list[tuple[int, int]] = []
        start = None
        gap = 0
        for i, is_hot in enumerate(hot):
            if is_hot:
                if start is None:
                    start = i
                gap = 0
            elif start is not None:
                gap += 1
                if gap > cfg.gap_tolerance:
                    runs.append((start, i - gap))
                    start, gap = None, 0
        if start is not None:
            runs.append((start, usable))

        out = []
        for lo, hi in runs:
            length = hi - lo
            if length < cfg.min_span_bytes:
                continue
            hi = min(hi, lo + cfg.max_span_bytes)
            # Drop trivial spans here, before the stability gate: null padding is
            # present in every PE, so it would sail through the gate with maximal
            # support and burn the expensive byte search on garbage.
            if trivial_hex_reason(_hex_body(window_bytes[lo:hi])):
                continue
            out.append((lo, hi))
        return out

    def spans_for_sample(
        self,
        ref: SampleRef,
        family: str | None,
        sections: Sequence[dict] | None = None,
    ) -> list[AttributedSpan]:
        """Attributed spans from one sample, both heads."""
        cfg = self.config
        windows, offsets = self._load_windows(ref, sections)
        if windows.numel() == 0:
            return []

        contribution, out = self._window_scores(windows)
        score_binary = float(torch.sigmoid(out["logit_binary"][0].float()).cpu())

        # Family attribution targets the ARGMAX class, never the true label.
        #
        # This is forced by the leakage protocol, and getting it wrong would be a
        # silent train/deploy mismatch. The family head's classes are F_train
        # families only, but rules are built for F_dev/F_test families -- which
        # have no class at all. Targeting the true label would make
        # attribution_fam a real number while ISB-A's scorer trains on F_train and
        # exactly 0.0 at deployment on eval families: the scorer would learn to
        # lean on a feature that vanishes when it matters.
        #
        # Using the argmax class gives the score one consistent meaning in both
        # settings -- "bytes driving this sample's family assignment, whatever
        # class that is" -- so for an unseen family it reports the bytes shared
        # with its nearest known family. Weaker signal, but honest and stationary.
        probs = torch.softmax(out["logits_family"][0].float(), dim=-1)
        class_index = int(probs.argmax().item())
        score_family = float(probs[class_index].cpu())
        if self.config.family_target == "true" and family in self.family_names:
            class_index = self.family_names.index(family)
            score_family = float(probs[class_index].cpu())

        order = np.argsort(-contribution)[: cfg.top_k_windows]
        spans: list[AttributedSpan] = []
        for w in order:
            window = windows[0, w]
            raw_window = bytes(
                int(b) for b in window.tolist() if int(b) != PAD_BYTE)
            if len(raw_window) < cfg.min_span_bytes:
                continue

            targets: list[tuple[str, int | None]] = [
                ("binary", None), ("family", class_index)]

            for target, ci in targets:
                saliency = self._integrated_gradients(window, target, ci)
                for lo, hi in self._runs(saliency, raw_window):
                    raw = raw_window[lo:hi]
                    if len(raw) < cfg.min_span_bytes:
                        continue
                    spans.append(AttributedSpan(
                        hex_body=_hex_body(raw),
                        raw=raw,
                        file_offset=offsets[w] + lo,
                        sha256=ref.sha256,
                        score_binary=score_binary if target == "binary" else 0.0,
                        score_family=score_family if target == "family" else 0.0,
                    ))

        # Merge duplicates from the two heads, keeping the max of each score.
        merged: dict[str, AttributedSpan] = {}
        for span in spans:
            existing = merged.get(span.hex_body)
            if existing is None:
                merged[span.hex_body] = span
            else:
                existing.score_binary = max(existing.score_binary,
                                            span.score_binary)
                existing.score_family = max(existing.score_family,
                                            span.score_family)
        out_spans = sorted(
            merged.values(),
            key=lambda s: (-(s.score_family + s.score_binary), s.hex_body),
        )
        return out_spans[: cfg.max_spans_per_sample]

    # -- the stability gate -------------------------------------------
    def stability_threshold(self, n_gen: int) -> int:
        """``m = max(floor, frac * n_gen)`` -- the EXP2_DESIGN §4 default."""
        import math
        cfg = self.config
        return max(cfg.stability_floor, int(math.ceil(cfg.stability_frac * n_gen)))

    def gate_by_stability(
        self,
        spans: Iterable[AttributedSpan],
        refs: Sequence[SampleRef],
        m: int | None = None,
    ) -> list[AttributedSpan]:
        """Keep spans present in >= m of the family's gen samples.

        Presence is an actual byte search across the gen samples, not a
        re-attribution: the question is "does this sequence occur in the family",
        which is exactly what the eventual YARA rule will ask.
        """
        spans = list(spans)
        if not spans:
            return []
        n_gen = len(refs)
        m = m if m is not None else self.stability_threshold(n_gen)

        needles = {span.hex_body: span.raw for span in spans}
        support: dict[str, int] = {k: 0 for k in needles}
        for ref in refs:
            data = self._read_capped(ref.path)
            if not data:
                continue
            for key, needle in needles.items():
                if needle and needle in data:
                    support[key] += 1

        kept = []
        for span in spans:
            span.support = support.get(span.hex_body, 0)
            span.n_gen = n_gen
            if span.support >= m:
                kept.append(span)
        kept.sort(key=lambda s: (-s.support,
                                 -(s.score_family + s.score_binary), s.hex_body))
        return kept

    def _read_capped(self, path: str) -> bytes:
        try:
            with open(path, "rb") as fh:       # static read only -- SAFETY
                return fh.read(self.config.presence_read_cap)
        except OSError:
            return b""

    # -- family entry point -------------------------------------------
    def candidates_for_family(
        self,
        family: str,
        gen_refs: Sequence[SampleRef],
        sections_of: Callable[[str], Any] | None = None,
        m: int | None = None,
    ) -> list[Candidate]:
        """Full pipeline for one family: attribute -> merge -> gate -> Candidate."""
        pooled: dict[str, AttributedSpan] = {}
        for ref in gen_refs:
            sections = None
            if sections_of is not None and self.sampler.stratify == "sections":
                try:
                    sections = sections_of(ref.sha256)
                except Exception:
                    sections = None
            for span in self.spans_for_sample(ref, family, sections):
                existing = pooled.get(span.hex_body)
                if existing is None:
                    pooled[span.hex_body] = span
                else:
                    existing.score_binary = max(existing.score_binary,
                                                span.score_binary)
                    existing.score_family = max(existing.score_family,
                                                span.score_family)

        gated = self.gate_by_stability(pooled.values(), gen_refs, m=m)
        return [span.to_candidate() for span in gated]

"""Window-strided MalConv with two heads (EXP2_DESIGN §4).

Shape of the idea::

    file ──► N sampled windows ──► shared conv encoder ──► N window embeddings
                                                              │
                                                    ┌─ pooling (max | attention)
                                                    ▼
                                              file embedding
                                                    ├──► binary head  (malware?)
                                                    └──► family head  (which?)

Three properties matter, and each is a deliberate departure from classic MalConv:

1. **No truncation bias.** MalConv reads the first 2MB; anything later is
   invisible to both prediction and attribution. Here the encoder is shared across
   windows drawn from the whole file, so a marker in a resource section at offset
   40MB is as reachable as one in ``.text``.
2. **Attribution is built in at window granularity.** Pooling keeps per-window
   contributions, so "which window mattered" is read straight off the forward
   pass -- no post-hoc surrogate. Integrated gradients then localise *within* the
   winning windows.
3. **Two heads, one backbone.** Malware-ness and family-specificity are different
   questions -- a packer stub predicts "malware", an family-unique C2 string
   predicts "which malware" -- and ISB-A wants both scores per candidate. The
   family loss is masked for unlabeled samples (vault, singletons) so unlabeled
   mass can still train the binary head.
"""

from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.nn.functional as F

__all__ = ["ModelConfig", "WindowMalConv", "masked_family_loss"]

#: 256 byte values + one padding symbol.
PAD_BYTE = 256
VOCAB = 257


@dataclass(frozen=True)
class ModelConfig:
    embed_dim: int = 8
    channels: int = 128
    kernel_size: int = 512
    stride: int = 512
    n_families: int = 23
    pooling: str = "attention"       # attention | max
    hidden: int = 256
    dropout: float = 0.2
    #: Loss weight on the family head: ``L_bin + family_loss_weight * L_fam``.
    family_loss_weight: float = 0.5


class WindowMalConv(nn.Module):
    """Shared-weight conv encoder over byte windows, pooled to two heads.

    Input is ``(batch, n_windows, window_size)`` of byte values, with
    :data:`PAD_BYTE` marking padding, plus a ``(batch, n_windows)`` bool mask of
    which windows are real. Samples in a batch have different window counts (small
    files yield fewer), so masking is load-bearing, not cosmetic: unmasked padding
    would let file size leak into the prediction.
    """

    def __init__(self, config: ModelConfig | None = None):
        super().__init__()
        self.config = config or ModelConfig()
        c = self.config

        self.embed = nn.Embedding(VOCAB, c.embed_dim, padding_idx=PAD_BYTE)
        # MalConv's gated convolution: one branch produces values, the other a
        # sigmoid gate, so the encoder can learn to ignore filler regions.
        self.conv_value = nn.Conv1d(c.embed_dim, c.channels, c.kernel_size,
                                    stride=c.stride)
        self.conv_gate = nn.Conv1d(c.embed_dim, c.channels, c.kernel_size,
                                   stride=c.stride)

        if c.pooling == "attention":
            self.attn = nn.Linear(c.channels, 1)
        else:
            self.attn = None

        self.trunk = nn.Sequential(
            nn.Linear(c.channels, c.hidden),
            nn.ReLU(),
            nn.Dropout(c.dropout),
        )
        self.head_binary = nn.Linear(c.hidden, 1)
        self.head_family = nn.Linear(c.hidden, c.n_families)

    # -- pieces --------------------------------------------------------
    def encode_windows(self, windows: torch.Tensor) -> torch.Tensor:
        """``(B, W, L)`` byte ids -> ``(B, W, channels)`` window embeddings."""
        b, w, length = windows.shape
        x = self.embed(windows.reshape(b * w, length))     # (B*W, L, E)
        x = x.transpose(1, 2)                              # (B*W, E, L)
        value = self.conv_value(x)
        gate = torch.sigmoid(self.conv_gate(x))
        h = value * gate                                   # (B*W, C, L')
        h = F.max_pool1d(h, kernel_size=h.shape[-1]).squeeze(-1)   # (B*W, C)
        return h.reshape(b, w, -1)

    def encode_from_embeddings(self, emb: torch.Tensor) -> torch.Tensor:
        """``(B, W, L, E)`` embeddings -> ``(B, W, channels)``.

        Split out of :meth:`encode_windows` so integrated gradients can be taken
        with respect to the byte embeddings: IG needs to interpolate between a
        baseline and the input in a differentiable space, and byte ids are
        discrete. Everything after the embedding lookup is shared, so attribution
        sees exactly the network that made the prediction.
        """
        b, w, length, e = emb.shape
        x = emb.reshape(b * w, length, e).transpose(1, 2)
        value = self.conv_value(x)
        gate = torch.sigmoid(self.conv_gate(x))
        h = value * gate
        h = F.max_pool1d(h, kernel_size=h.shape[-1]).squeeze(-1)
        return h.reshape(b, w, -1)

    def heads_from_windows(
        self, window_emb: torch.Tensor, mask: torch.Tensor
    ) -> dict[str, torch.Tensor]:
        """Window embeddings -> both head logits (used by attribution)."""
        pooled, contribution = self.pool(window_emb, mask)
        feat = self.trunk(pooled)
        return {
            "logit_binary": self.head_binary(feat).squeeze(-1),
            "logits_family": self.head_family(feat),
            "window_contribution": contribution,
        }

    def pool(
        self, window_emb: torch.Tensor, mask: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Pool windows to a file embedding.

        Returns ``(file_emb, window_contribution)``. The contribution tensor is
        the attribution entry point: attention weights when pooling is attention,
        and the share of pooled dimensions a window won when pooling is max.
        """
        neg_inf = torch.finfo(window_emb.dtype).min
        mask_f = mask.unsqueeze(-1)                        # (B, W, 1)

        if self.attn is not None:
            scores = self.attn(window_emb).squeeze(-1)     # (B, W)
            scores = scores.masked_fill(~mask, neg_inf)
            weights = torch.softmax(scores, dim=1)
            weights = weights * mask                      # zero out padding
            weights = weights / weights.sum(dim=1, keepdim=True).clamp_min(1e-9)
            pooled = (window_emb * weights.unsqueeze(-1)).sum(dim=1)
            return pooled, weights

        masked = window_emb.masked_fill(~mask_f, neg_inf)
        pooled, argmax = masked.max(dim=1)                 # (B, C), (B, C)
        # Fraction of channels for which this window was the maximum.
        contribution = torch.zeros_like(window_emb[..., 0])
        contribution.scatter_add_(
            1, argmax, torch.ones_like(argmax, dtype=contribution.dtype))
        contribution = contribution / max(1, window_emb.shape[-1])
        return pooled, contribution

    def forward(
        self, windows: torch.Tensor, mask: torch.Tensor | None = None
    ) -> dict[str, torch.Tensor]:
        if mask is None:
            mask = torch.ones(windows.shape[:2], dtype=torch.bool,
                              device=windows.device)
        window_emb = self.encode_windows(windows)
        pooled, contribution = self.pool(window_emb, mask)
        feat = self.trunk(pooled)
        return {
            "logit_binary": self.head_binary(feat).squeeze(-1),   # (B,)
            "logits_family": self.head_family(feat),              # (B, n_fam)
            "window_contribution": contribution,                  # (B, W)
            "window_embeddings": window_emb,                      # (B, W, C)
            "file_embedding": pooled,                             # (B, C)
        }

    # -- loss ----------------------------------------------------------
    def loss(
        self,
        out: dict[str, torch.Tensor],
        labels: torch.Tensor,
        family: torch.Tensor,
        weights: torch.Tensor | None = None,
        pos_weight: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        """``L_bin + family_loss_weight * L_fam``, family loss masked.

        ``weights`` carries the per-sample weight (the vault arm's 0.3);
        ``pos_weight`` corrects the ~8:1 goodware:malware imbalance in the
        training mix.
        """
        bin_loss = F.binary_cross_entropy_with_logits(
            out["logit_binary"], labels.float(), reduction="none",
            pos_weight=pos_weight,
        )
        if weights is not None:
            bin_loss = bin_loss * weights
            l_bin = bin_loss.sum() / weights.sum().clamp_min(1e-9)
        else:
            l_bin = bin_loss.mean()

        l_fam = masked_family_loss(out["logits_family"], family, weights)
        total = l_bin + self.config.family_loss_weight * l_fam
        return {"loss": total, "loss_binary": l_bin.detach(),
                "loss_family": l_fam.detach()}


def masked_family_loss(
    logits: torch.Tensor,
    family: torch.Tensor,
    weights: torch.Tensor | None = None,
    ignore_index: int = -1,
) -> torch.Tensor:
    """Cross-entropy over family-labeled samples only.

    Returns a real zero (not NaN) when a batch happens to contain no labeled
    sample -- which occurs regularly once the vault arm is in, and would otherwise
    poison the whole run's gradients.
    """
    valid = family != ignore_index
    if not bool(valid.any()):
        return logits.sum() * 0.0
    loss = F.cross_entropy(logits[valid], family[valid], reduction="none")
    if weights is not None:
        w = weights[valid]
        return (loss * w).sum() / w.sum().clamp_min(1e-9)
    return loss.mean()

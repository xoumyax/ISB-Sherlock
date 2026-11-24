"""Torch ``Dataset``/collate over :class:`~.data.SampleRef` lists.

Kept separate from :mod:`.data` so the leakage guards and split logic stay
importable without torch -- they get exercised in tests and by CPU drivers that
have no business loading CUDA.

Per-epoch window resampling is the augmentation mechanism (EXP2_DESIGN §4): call
:meth:`WindowDataset.set_epoch` each epoch and every sample yields a different
window subset from the same file. With ~12k training samples that matters more
than any regulariser.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence

import numpy as np
import torch
from torch.utils.data import Dataset

from .data import FAMILY_UNLABELED, SampleRef, WindowSampler, read_windows
from .model import PAD_BYTE

__all__ = ["WindowDataset", "collate_windows"]


class WindowDataset(Dataset):
    """Yields ``(windows, mask, label, family, weight)`` per sample.

    ``sections_of`` is an optional callable ``sha256 -> sections list`` (normally
    ``ExtractionCache.get(sha)["sections"]``) used only by section-stratified
    sampling; ``None`` falls back to uniform stratification, which needs no
    metadata and does not trust a section table that packers routinely falsify.
    """

    def __init__(
        self,
        refs: Sequence[SampleRef],
        sampler: WindowSampler | None = None,
        sections_of: Callable[[str], Any] | None = None,
        epoch: int = 0,
    ):
        self.refs = list(refs)
        self.sampler = sampler or WindowSampler()
        self.sections_of = sections_of
        self.epoch = epoch

    def set_epoch(self, epoch: int) -> None:
        self.epoch = epoch

    def __len__(self) -> int:
        return len(self.refs)

    def __getitem__(self, index: int) -> dict[str, Any]:
        ref = self.refs[index]
        sections = None
        if self.sections_of is not None and self.sampler.stratify == "sections":
            try:
                sections = self.sections_of(ref.sha256)
            except Exception:
                sections = None

        chunks = read_windows(
            ref.path, self.sampler, epoch=self.epoch,
            sha256=ref.sha256, sections=sections,
        )
        if not chunks:
            # Unreadable sample: one all-padding window, fully masked out. Keeps
            # the batch shape valid and contributes no gradient, instead of
            # crashing an epoch over one bad file.
            arr = np.full((1, self.sampler.window_size), PAD_BYTE, dtype=np.int64)
            mask = np.zeros((1,), dtype=bool)
        else:
            arr = np.full((len(chunks), self.sampler.window_size), PAD_BYTE,
                          dtype=np.int64)
            for i, chunk in enumerate(chunks):
                buf = np.frombuffer(chunk, dtype=np.uint8)
                arr[i, : len(buf)] = buf
            mask = np.ones((len(chunks),), dtype=bool)

        return {
            "windows": torch.from_numpy(arr),
            "mask": torch.from_numpy(mask),
            "label": float(ref.label),
            "family": int(ref.family_index),
            "weight": float(ref.weight),
            "sha256": ref.sha256,
        }


def collate_windows(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Pad to the batch's max window count.

    Window counts differ per sample (a 40KB file yields one window, a 400MB file
    yields the cap), so padded slots are marked ``False`` in the mask and the
    model's pooling excludes them -- otherwise file size would leak into the
    prediction through the padding.
    """
    n_max = max(item["windows"].shape[0] for item in batch)
    window_size = batch[0]["windows"].shape[1]

    windows = torch.full((len(batch), n_max, window_size), PAD_BYTE,
                         dtype=torch.long)
    mask = torch.zeros((len(batch), n_max), dtype=torch.bool)
    for i, item in enumerate(batch):
        n = item["windows"].shape[0]
        windows[i, :n] = item["windows"]
        mask[i, :n] = item["mask"]

    return {
        "windows": windows,
        "mask": mask,
        "labels": torch.tensor([item["label"] for item in batch],
                               dtype=torch.float),
        "family": torch.tensor([item["family"] for item in batch],
                               dtype=torch.long),
        "weights": torch.tensor([item["weight"] for item in batch],
                                dtype=torch.float),
        "sha256": [item["sha256"] for item in batch],
    }


def family_ignore_index() -> int:
    """The ignore index the family loss uses (kept in one place)."""
    return FAMILY_UNLABELED

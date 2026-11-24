"""
Optional EMBER2024 / thrember integration helpers.

The thrember package is deliberately imported lazily. EMBER2024 downloads can
be large, so these helpers expose explicit planning and download calls instead
of doing anything at import time.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


VALID_EMBER2024_SPLITS = ("all", "train", "test", "challenge")
VALID_EMBER2024_FILE_TYPES = ("all", "PE", "Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF")

_FILE_TYPE_EXPANSIONS = {
    "all": ("Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF"),
    "PE": ("Win32", "Win64", "Dot_Net"),
    "Win32": ("Win32",),
    "Win64": ("Win64",),
    "Dot_Net": ("Dot_Net",),
    "APK": ("APK",),
    "ELF": ("ELF",),
    "PDF": ("PDF",),
}

_SPLIT_EXPANSIONS = {
    "all": ("train", "test", "challenge"),
    "train": ("train",),
    "test": ("test",),
    "challenge": ("challenge",),
}

# Approximate compressed feature+label sizes published by EMBER2024.
_SUBSET_SIZE_MB = {
    ("Win32", "train"): 23700,
    ("Win32", "test"): 4900,
    ("Win64", "train"): 12900,
    ("Win64", "test"): 2500,
    ("Dot_Net", "train"): 1800,
    ("Dot_Net", "test"): 425,
    ("APK", "train"): 1000,
    ("APK", "test"): 234,
    ("PDF", "train"): 197,
    ("PDF", "test"): 46,
    ("ELF", "train"): 100,
    ("ELF", "test"): 24,
    ("challenge", "challenge"): 126,
}


@dataclass
class Ember2024Plan:
    download_dir: str
    split: str
    file_type: str
    expanded_splits: list[str]
    expanded_file_types: list[str]
    estimated_size: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ember2024_download_plan(
    download_dir: str | Path,
    *,
    split: str = "challenge",
    file_type: str = "PE",
) -> Ember2024Plan:
    """Return a dry-run summary for an EMBER2024 dataset download."""
    _validate_ember2024_args(split=split, file_type=file_type)
    expanded_splits = list(_SPLIT_EXPANSIONS[split])
    expanded_file_types = list(_FILE_TYPE_EXPANSIONS[file_type])
    size_mb = _estimate_size_mb(expanded_splits, expanded_file_types)
    note = (
        "challenge is file-type agnostic"
        if expanded_splits == ["challenge"]
        else "sizes are approximate compressed feature+label archives"
    )
    return Ember2024Plan(
        download_dir=str(download_dir),
        split=split,
        file_type=file_type,
        expanded_splits=expanded_splits,
        expanded_file_types=expanded_file_types,
        estimated_size=_format_size(size_mb),
        note=note,
    )


def download_ember2024_dataset(
    download_dir: str | Path,
    *,
    split: str = "challenge",
    file_type: str = "PE",
) -> Ember2024Plan:
    """Download EMBER2024 features/labels through thrember."""
    plan = ember2024_download_plan(download_dir, split=split, file_type=file_type)
    thrember = _require_thrember()
    target = Path(download_dir)
    target.mkdir(parents=True, exist_ok=True)
    cwd = Path.cwd()
    try:
        thrember.download_dataset(str(target), split=split, file_type=file_type)
    finally:
        os.chdir(cwd)
    return plan


def download_ember2024_models(download_dir: str | Path) -> dict[str, Any]:
    """Download EMBER2024 benchmark LightGBM models through thrember."""
    thrember = _require_thrember()
    target = Path(download_dir)
    target.mkdir(parents=True, exist_ok=True)
    cwd = Path.cwd()
    try:
        thrember.download_models(str(target))
    finally:
        os.chdir(cwd)
    return {
        "download_dir": str(target),
        "model_glob": "*.model",
        "note": "EMBER2024 benchmark LightGBM models downloaded via thrember.",
    }


def vectorize_ember2024_dataset(
    data_dir: str | Path,
    *,
    label_type: str = "label",
    class_min: int = 10,
) -> dict[str, Any]:
    """Create thrember .dat vector files for downloaded EMBER2024 JSONL files."""
    thrember = _require_thrember()
    thrember.create_vectorized_features(str(data_dir), label_type=label_type, class_min=class_min)
    return {
        "data_dir": str(data_dir),
        "label_type": label_type,
        "class_min": class_min,
        "outputs": ["X_train.dat", "y_train.dat", "X_test.dat", "y_test.dat", "X_challenge.dat", "y_challenge.dat"],
    }


def read_ember2024_vectorized_features(data_dir: str | Path, *, subset: str = "train"):
    """Read thrember vectorized features as numpy arrays."""
    thrember = _require_thrember()
    return thrember.read_vectorized_features(str(data_dir), subset=subset)


def _require_thrember():
    try:
        import thrember
    except ImportError as exc:
        raise ImportError(
            "EMBER2024 support requires thrember. Install it from "
            "https://github.com/FutureComputing4AI/EMBER2024 with `pip install .`."
        ) from exc
    return thrember


def _validate_ember2024_args(*, split: str, file_type: str) -> None:
    if split not in VALID_EMBER2024_SPLITS:
        raise ValueError(f"split must be one of: {', '.join(VALID_EMBER2024_SPLITS)}")
    if file_type not in VALID_EMBER2024_FILE_TYPES:
        raise ValueError(f"file_type must be one of: {', '.join(VALID_EMBER2024_FILE_TYPES)}")


def _estimate_size_mb(splits: list[str], file_types: list[str]) -> int:
    if splits == ["challenge"]:
        return _SUBSET_SIZE_MB[("challenge", "challenge")]
    total = 0
    for split in splits:
        if split == "challenge":
            total += _SUBSET_SIZE_MB[("challenge", "challenge")]
            continue
        for file_type in file_types:
            total += _SUBSET_SIZE_MB.get((file_type, split), 0)
    return total


def _format_size(size_mb: int) -> str:
    if size_mb >= 1000:
        return f"{size_mb / 1000:.1f} GB"
    return f"{size_mb} MB"

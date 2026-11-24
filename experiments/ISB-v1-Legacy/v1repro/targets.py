"""Scan targets: V1's split files, resolved by sha256 through the Sherlock manifest.

V1 joined ``corpus_root`` with each split entry's ``path``. The layouts differ
here, so each sha256 is looked up in ``ISB_DATA/metadata/sherlock_manifest.csv``
and its ``dataset_path`` (relative to the dataset root) is used instead. Nothing
is filtered on the manifest's pool/kind/flags. Labels come from V1's split
only: family and side for malware, ``source`` for goodware.
"""

from __future__ import annotations

import csv
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_REL = "metadata/sherlock_manifest.csv"


@dataclass(frozen=True)
class ManifestEntry:
    dataset_path: str
    size: int | None


@dataclass(frozen=True)
class TargetSpec:
    """One target before it becomes a harness ``ScanTarget``."""

    sha256: str
    path: str
    kind: str
    family: str | None = None
    source: str | None = None


def dataset_root() -> Path:
    """The dataset root, from env ``ISB_DATA`` only. There is no default."""
    root = os.environ.get("ISB_DATA", "").strip()
    if not root:
        raise RuntimeError("ISB_DATA is not set; there is no default dataset root")
    return Path(root)


def _safe_rel(rel: str) -> str:
    p = PurePosixPath(rel)
    if not rel or p.is_absolute() or ".." in p.parts:
        raise ValueError(f"unsafe dataset_path {rel!r}")
    return rel


def load_manifest(path: Path) -> dict[str, ManifestEntry]:
    """sha256 -> entry. A sha listed twice with different paths is an error."""
    out: dict[str, ManifestEntry] = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            sha = row["sha256"].strip().lower()
            entry = ManifestEntry(
                _safe_rel(row["dataset_path"].strip()),
                int(row["size"]) if row.get("size") else None,
            )
            if sha in out and out[sha].dataset_path != entry.dataset_path:
                raise ValueError(
                    f"manifest lists a sha twice with different paths: "
                    f"{out[sha].dataset_path} / {entry.dataset_path}"
                )
            out[sha] = entry
    return out


def split_selection(
    mal: Mapping[str, Any], good: Mapping[str, Any], split: str = "F_dev"
) -> dict[str, list[dict[str, Any]]]:
    """V1's target selection, exactly as ``run_exp2.stage_score`` did it.

    Held/gen: ``split`` matches and ``is_pe``; side "held" is held, any other
    side is gen. Goodware: side ``G_eval`` with a ``path``. Sorted by sha.
    """
    held, gen = [], []
    for sha, info in sorted(mal["samples"].items()):
        if info.get("split") != split or not info.get("is_pe"):
            continue
        rec = {
            "sha256": sha,
            "kind": info.get("side") or "?",
            "family": info.get("family"),
        }
        (held if info.get("side") == "held" else gen).append(rec)
    goodware = [
        {"sha256": sha, "kind": "goodware", "source": v.get("source")}
        for sha, v in sorted(good["samples"].items())
        if v.get("side") == "G_eval" and v.get("path")
    ]
    return {"held": held, "gen": gen, "goodware": goodware}


def resolve(
    selection: Mapping[str, list[dict[str, Any]]],
    manifest: Mapping[str, ManifestEntry],
    root: Path,
) -> tuple[dict[str, list[TargetSpec]], list[str]]:
    """Attach dataset paths; return (targets per corpus, unresolved corpus:index)."""
    out: dict[str, list[TargetSpec]] = {}
    unresolved: list[str] = []
    root_r = Path(os.path.realpath(root))
    for corpus, recs in selection.items():
        specs = []
        for i, rec in enumerate(recs):
            entry = manifest.get(rec["sha256"].lower())
            if entry is None:
                unresolved.append(f"{corpus}:{i}")
                continue
            path = root_r / entry.dataset_path
            specs.append(
                TargetSpec(
                    sha256=rec["sha256"],
                    path=str(path),
                    kind=rec["kind"],
                    family=rec.get("family"),
                    source=rec.get("source"),
                )
            )
        out[corpus] = specs
    return out, unresolved


def stat_coverage(
    targets: Mapping[str, list[TargetSpec]], manifest: Mapping[str, ManifestEntry]
) -> dict[str, Any]:
    """Stat-only check: exists, regular file, size equals the manifest's. No reads."""
    report: dict[str, Any] = {}
    for corpus, specs in targets.items():
        missing = not_regular = size_mismatch = 0
        for t in specs:
            try:
                st = os.stat(t.path)
            except FileNotFoundError:
                missing += 1
                continue
            if not os.path.isfile(t.path):
                not_regular += 1
                continue
            expected = manifest[t.sha256.lower()].size
            if expected is not None and st.st_size != expected:
                size_mismatch += 1
        report[corpus] = {
            "n": len(specs),
            "missing": missing,
            "not_regular_file": not_regular,
            "size_mismatch": size_mismatch,
            "ok": len(specs) - missing - not_regular - size_mismatch,
        }
    return report

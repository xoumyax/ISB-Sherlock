"""Migration acceptance: count the dataset on disk and in the manifest, read-only.

One-off session-1 check (docs/migration/ACCEPTANCE.md). Compares per-folder file
counts on disk with per-``folder`` row counts in ``metadata/sherlock_manifest.csv``,
checks that every ``dataset_path`` exists and that every file on disk has a row, and
hashes a seeded random sample of sample files against their names. It only reads
bytes (hashing); it never executes or modifies anything under the dataset root.

Usage (from ``Sherlock/``, roots from the environment or config/roots.yaml):

    python -I scripts/migration/acceptance_counts.py DATASET_ROOT OUT_JSON

Standard library only, so it runs before the ``sherlock`` package exists.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import sys
from collections import Counter

__all__ = ["main"]

SEED = 20261123  #: fixed so the 1,000-file hash sample is reproducible
N_HASH = 1000


# -- disk -----------------------------------------------------------------------


def _folder_of(rel: str) -> str:
    """Manifest-style folder of a dataset-relative file path."""
    parts = rel.split("/")
    if parts[0] == "malware" and parts[1] == "_unlabelled":
        return "/".join(parts[:3])
    return "/".join(parts[:2])


def _walk(root: str) -> tuple[Counter[str], list[str], list[str]]:
    counts: Counter[str] = Counter()
    files: list[str] = []
    other: list[str] = []
    for top in ("malware", "goodware"):
        for dirpath, _dirs, names in os.walk(os.path.join(root, top)):
            for name in names:
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                if name.endswith(".bin") and len(name) == 68:
                    counts[_folder_of(rel)] += 1
                    files.append(rel)
                else:
                    other.append(rel)
    return counts, files, other


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(8 << 20), b""):
            h.update(block)
    return h.hexdigest()


# -- main -----------------------------------------------------------------------


def main(root: str, out: str) -> int:
    disk, files, other = _walk(root)
    csv.field_size_limit(1 << 30)
    with open(os.path.join(root, "metadata", "sherlock_manifest.csv"), newline="") as f:
        rows = list(csv.DictReader(f))

    by_folder = Counter(r["folder"] for r in rows)
    paths = {r["dataset_path"] for r in rows}
    shas = Counter(r["sha256"] for r in rows)
    missing = sorted(
        r["dataset_path"]
        for r in rows
        if not os.path.exists(os.path.join(root, r["dataset_path"]))
    )
    name_mismatch = [
        r["sha256"]
        for r in rows
        if os.path.basename(r["dataset_path"]) != f"{r['sha256']}.bin"
    ]
    unlisted = sorted(set(files) - paths)

    flags: Counter[str] = Counter()
    for r in rows:
        for flag in filter(None, r["flags"].split(";")):
            flags[flag] += 1

    fam = {
        k: v
        for k, v in disk.items()
        if k.startswith("malware/") and not k.startswith("malware/_")
    }
    buckets = Counter(
        "ge100"
        if n >= 100
        else "40-99"
        if n >= 40
        else "20-39"
        if n >= 20
        else "10-19"
        if n >= 10
        else "1-9"
        for n in fam.values()
    )

    sample = random.Random(SEED).sample(sorted(files), N_HASH)
    bad_hash = [
        p for p in sample if _sha256(os.path.join(root, p)) != os.path.basename(p)[:-4]
    ]

    folders = sorted(set(disk) | set(by_folder))
    report = {
        "seed": SEED,
        "disk_files": len(files),
        "disk_other_files": other[:50],
        "n_disk_other_files": len(other),
        "manifest_rows": len(rows),
        "manifest_unique_sha256": len(shas),
        "manifest_duplicate_sha256": [s for s, n in shas.items() if n > 1],
        "missing_dataset_paths": missing,
        "name_mismatch_rows": name_mismatch,
        "disk_files_without_row": unlisted,
        "per_folder": {
            k: {"disk": disk.get(k, 0), "manifest": by_folder.get(k, 0)}
            for k in folders
        },
        "per_folder_disagree": [
            k for k in folders if disk.get(k, 0) != by_folder.get(k, 0)
        ],
        "family_folders": len(fam),
        "family_files": sum(fam.values()),
        "family_size_buckets": dict(buckets),
        "by_pool": dict(Counter(r["pool"] for r in rows)),
        "by_folder_basis": dict(Counter(r["folder_basis"] for r in rows)),
        "by_kind_pool": dict(
            sorted(Counter(f"{r['pool']}:{r['kind']}" for r in rows).items())
        ),
        "flags": dict(flags),
        "hash_sample_n": len(sample),
        "hash_sample_mismatches": bad_hash,
    }
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(report, f, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))

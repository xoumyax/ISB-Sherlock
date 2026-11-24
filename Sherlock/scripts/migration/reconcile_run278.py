"""Migration acceptance: reconcile sherlock_manifest.csv with manifest run 278.

One-off session-1 check (docs/migration/ACCEPTANCE.md §4). The dashboard's figures
(117,944 files: 95,701 malware, 22,243 goodware) are the ``files`` table of the
checkpoint ``manifest.sqlite``; the migrated dataset has 117,999. This script
explains the difference sha256 by sha256, recounts the snapshot's per-origin and
label-regime figures from the CSV, and checks that the DB-only files that still had
paths are the export files now under ``metadata/``.

Usage (read-only on both inputs; the DB is opened with ``mode=ro``):

    python -I scripts/migration/reconcile_run278.py DATASET_ROOT MANIFEST_DB OUT_JSON

Standard library only, so it runs before the ``sherlock`` package exists.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
import sys
from collections import Counter

__all__ = ["main"]

EXE = ("pe", "dotnet", "elf")


def _ge(counts: Counter[str], ks: tuple[int, ...] = (10, 20, 40, 80)) -> dict[str, int]:
    return {f"ge{k}": sum(v >= k for v in counts.values()) for k in ks}


def main(root: str, db: str, out: str) -> int:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    csv.field_size_limit(1 << 30)
    with open(os.path.join(root, "metadata", "sherlock_manifest.csv"), newline="") as f:
        rows = {r["sha256"]: r for r in csv.DictReader(f)}
    q = "select sha256, pool, kind from files"
    files = {s: (p, k) for s, p, k in con.execute(q)}

    only_csv = sorted(set(rows) - set(files))
    only_db = sorted(set(files) - set(rows))
    db_with_path = [
        s
        for s in only_db
        if con.execute("select 1 from file_paths where sha256=?", (s,)).fetchone()
    ]

    in_meta: dict[str, str] = {}
    for dirpath, _dirs, names in os.walk(os.path.join(root, "metadata")):
        for name in names:
            p = os.path.join(dirpath, name)
            with open(p, "rb") as fh:
                h = hashlib.sha256(fh.read()).hexdigest()
            if h in files and h not in rows:
                in_meta[h] = os.path.relpath(p, root)

    origin_exe_gw: Counter[str] = Counter()
    origin_mw: Counter[str] = Counter()
    for r in rows.values():
        for o in filter(None, r["origins"].split(";")):
            if r["pool"] == "goodware" and r["kind"] in EXE:
                origin_exe_gw[o] += 1
            if r["pool"] == "malware" and r["kind"] != "uninventoried":
                origin_mw[o] += 1

    tier_x = [r for r in rows.values() if r["mb_family"] and r["kind"] in EXE]
    tier_x_runs = [
        r
        for r in tier_x
        if any(o.startswith("bazaar_run") for o in r["origins"].split(";"))
    ]
    tier_a = [r for r in rows.values() if r["motif_tier"] == "A"]
    pc = [s for s, r in rows.items() if r["folder_basis"] == "pool_conflict"]

    report = {
        "csv_rows": len(rows),
        "db_files": len(files),
        "db_by_pool": dict(Counter(p for p, _ in files.values())),
        "csv_by_pool": dict(Counter(r["pool"] for r in rows.values())),
        "only_csv": len(only_csv),
        "only_csv_by_pool_kind_flags": dict(
            Counter(
                f"{rows[s]['pool']}:{rows[s]['kind']}:{rows[s]['flags']}"
                for s in only_csv
            )
        ),
        "only_db": len(only_db),
        "only_db_by_pool_kind": dict(Counter(":".join(files[s]) for s in only_db)),
        "only_db_with_file_paths": len(db_with_path),
        "only_db_without_file_paths": len(only_db) - len(db_with_path),
        "only_db_found_under_metadata": dict(sorted(in_meta.items())),
        "pool_conflicts_csv": len(pc),
        "pool_conflicts_in_db": sum(s in files for s in pc),
        "pool_conflicts_db_pool": dict(Counter(files[s][0] for s in pc if s in files)),
        "goodware_exe_by_origin": dict(sorted(origin_exe_gw.items())),
        "malware_by_origin_excl_uninventoried": dict(sorted(origin_mw.items())),
        "tier_x_exe_all": len(tier_x),
        "tier_x_exe_runs_1_5": len(tier_x_runs),
        "tier_x_runs_1_5_families": _ge(Counter(r["mb_family"] for r in tier_x_runs))
        | {"n": len({r["mb_family"] for r in tier_x_runs})},
        "tier_x_all_families": _ge(Counter(r["mb_family"] for r in tier_x))
        | {"n": len({r["mb_family"] for r in tier_x})},
        "tier_a_samples": len(tier_a),
        "tier_a_families": _ge(Counter(r["motif_family"] for r in tier_a), (10, 20, 40))
        | {"n": len({r["motif_family"] for r in tier_a})},
    }
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(report, f, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))

#!/usr/bin/env python3
"""Check sha256(file) == file name for every <sha256>.bin listed (one dataset-relative path per line).

Usage: python3 -I verify_names.py DATASET_ROOT LIST_FILE
Reads bytes only (hashing); never executes or modifies anything. Exit 1 on any mismatch.
Also used on the destination cluster after unzipping.
"""
import hashlib
import os
import sys

root, lst = sys.argv[1], sys.argv[2]
bad = n = 0
with open(lst, errors="surrogateescape") as fh:
    for line in fh:
        rel = line.rstrip("\n")
        if not rel or not rel.endswith(".bin") or rel.startswith("metadata/"):
            continue
        h = hashlib.sha256()
        with open(os.path.join(root, rel), "rb") as f:
            for b in iter(lambda: f.read(8 << 20), b""):
                h.update(b)
        n += 1
        if h.hexdigest() != os.path.basename(rel)[:-4]:
            bad += 1
            print(f"MISMATCH {rel} {h.hexdigest()}", flush=True)
print(f"verified {n} files, {bad} mismatches", flush=True)
sys.exit(1 if bad else 0)

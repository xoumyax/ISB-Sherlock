"""Sherlock (ISB vN): pick the indicators for a YARA rule built from binaries.

Given a family's older samples, Sherlock writes a short rule that still fires on
the family's newer samples and never on goodware. It is written fresh in V1's style,
and not influenced by V1 (brownie, 23 Nov 2026): code is written from scratch,
keeping only V1's knowledge (style, and its lessons as guards against known bugs).
V1 is run afterwards as a baseline, never as a target. The plan is
in ``SHERLOCKED.md`` at the git root; the layout is in the git root's ``README.md``.

Built at G0: ``core.ir`` (the Candidate IR), ``core.records`` (run records),
``data.roots`` and ``data.manifest``. The other sub-packages are placeholders for
P3-P6. This package never imports ``yaramod``, numpy or anything heavy at import
time.
"""

from __future__ import annotations

from .core.ir import (
    ENCODINGS,
    KINDS,
    Candidate,
    Kind,
    Occurrence,
    read_candidates_jsonl,
    write_candidates_jsonl,
)
from .core.records import GitInfo, RunRecord, git_info, read_run_json
from .data.manifest import (
    LeakageError,
    Manifest,
    ManifestDB,
    ManifestRow,
    Split,
    require_training_families,
)
from .data.roots import Roots, RootsError, resolve_roots

__all__ = [
    # core.ir
    "Candidate", "Kind", "KINDS", "ENCODINGS", "Occurrence",
    "write_candidates_jsonl", "read_candidates_jsonl",
    # core.records
    "RunRecord", "GitInfo", "git_info", "read_run_json",
    # data.roots
    "Roots", "RootsError", "resolve_roots",
    # data.manifest
    "Manifest", "ManifestRow", "ManifestDB", "Split", "LeakageError",
    "require_training_families",
]  # fmt: skip

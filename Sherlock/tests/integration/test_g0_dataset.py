"""G0 on the real dataset: resolve samples by sha256 and round-trip Candidates.

Marked ``needs_data``: skipped unless ``ISB_DATA`` is set. Read-only: it opens the
working DB with ``mode=ro`` and writes only to ``tmp_path``. The counts pinned here
were measured in session 1 (2026-11-23, ``docs/migration/ACCEPTANCE.md``).
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from sherlock.core.ir import (
    Candidate,
    Kind,
    Occurrence,
    read_candidates_jsonl,
    write_candidates_jsonl,
)
from sherlock.data.manifest import Manifest, ManifestDB
from sherlock.data.roots import resolve_roots

pytestmark = pytest.mark.needs_data

SEED = 20261123
N = 1000


@pytest.fixture(scope="module")
def manifest() -> Manifest:
    return Manifest.load(resolve_roots())


def _sample(manifest: Manifest) -> list[str]:
    return random.Random(SEED).sample(sorted(manifest), N)


def test_manifest_size(manifest: Manifest) -> None:
    assert len(manifest) == 117_999


def test_resolve_1000_seeded_hashes(manifest: Manifest) -> None:
    shas = _sample(manifest)
    res = manifest.resolve_many(shas, check_exists=True)
    assert res, res.summary()
    assert len(res.paths) == N
    for sha, path in res.paths.items():
        assert path.name == f"{sha}.bin"
        assert path.resolve().is_relative_to(manifest.dataset_root.resolve())


def test_round_trip_1000_candidates(manifest: Manifest, tmp_path: Path) -> None:
    rng = random.Random(f"{SEED}:candidates")
    cands = []
    for sha in _sample(manifest):
        row = manifest.row(sha)
        occ = (Occurrence(sha, ".text", rng.randrange(1 << 20)),)
        meta = {"pool": row.pool, "tlsh": row.tlsh}
        pick = rng.randrange(4)
        if pick == 0:
            c = Candidate(
                Kind.TEXT,
                f"{row.kind}:{row.folder}",
                encoding="ascii",
                occurrences=occ,
                meta=meta,
            )
        elif pick == 1:
            c = Candidate(
                Kind.TEXT, row.folder, encoding="wide", occurrences=occ, meta=meta
            )
        elif pick == 2:
            c = Candidate.from_bytes(bytes.fromhex(sha[:16]), occurrences=occ)
        else:
            c = Candidate(
                Kind.PE_IMPORT,
                "CreateFileW",
                qualifier="KERNEL32.dll",
                occurrences=(Occurrence(sha),),
                meta=meta,
            )
        cands.append(c)
    path = tmp_path / "candidates.jsonl"
    assert write_candidates_jsonl(path, cands) == N
    back, dropped = read_candidates_jsonl(path)
    assert dropped == {}
    assert [c.to_dict() for c in back] == [c.to_dict() for c in cands]


def test_csv_db_coverage_matches_acceptance(manifest: Manifest) -> None:
    roots = resolve_roots()
    db_dir = roots.work / "manifest"
    before = {p.name: p.stat().st_mtime_ns for p in db_dir.iterdir()}
    with ManifestDB.open(roots) as db:
        join = db.fetch("files", list(manifest), columns=("pool",))
        cov = db.coverage(manifest)
    no_row = join.dropped["no_db_row"]
    assert len(no_row) == 85
    assert all("oversized_uninventoried" in manifest.row(s).flags for s in no_row)
    assert sorted(no_row) == cov.csv_only
    assert len(join.rows) == 117_999 - 85
    assert len(cov.db_only) == 30
    # Read-only: no file beside the DB created or touched, sidecars included.
    assert {p.name: p.stat().st_mtime_ns for p in db_dir.iterdir()} == before

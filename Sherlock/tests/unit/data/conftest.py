"""A tiny fake dataset for the ``sherlock.data`` unit tests.

Four CSV rows and a sqlite file shaped like the real ``manifest.sqlite``: one CSV
hash has no DB row (like the 85 ``oversized_uninventoried`` files) and one DB hash
has no CSV row (like the 30 MalwareBazaar export files).
"""

from __future__ import annotations

import csv
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

COLUMNS = (
    "sha256,dataset_path,folder,folder_basis,pool,kind,size,md5,sha1,tlsh,"
    "mb_family,mb_family_raw,mb_first_seen,mb_label_source,motif_family,"
    "motif_family_raw,motif_tier,die_packed,die_packer,origins,n_paths,flags,"
    "parent_sha256,v1_crosscheck"
).split(",")

SHA_PE = "1" * 64
SHA_GOOD = "2" * 64
SHA_UNINV = "3" * 64
SHA_CHILD = "4" * 64
SHA_DB_ONLY = "5" * 64


@dataclass(frozen=True)
class FakeDataset:
    root: Path
    csv_path: Path
    db_path: Path


def _row(sha: str, path: str, **kw: str) -> dict[str, str]:
    row = dict.fromkeys(COLUMNS, "")
    row.update(sha256=sha, dataset_path=path, size="10", n_paths="1")
    row.update(kw)
    return row


@pytest.fixture
def fake_dataset(tmp_path: Path) -> FakeDataset:
    root = tmp_path / "data"
    rows = [
        _row(
            SHA_PE,
            f"malware/agenttesla/{SHA_PE}.bin",
            folder="malware/agenttesla",
            pool="malware",
            kind="pe",
            tlsh="T1ABC",
            mb_family="agenttesla",
            mb_first_seen="2024-01-02 03:04:05",
            die_packed="1",
            die_packer="UPX",
            origins="bazaar_run4;vault_bb",
            flags="",
        ),
        _row(
            SHA_GOOD,
            f"goodware/cnet/{SHA_GOOD}.bin",
            folder="goodware/cnet",
            pool="goodware",
            kind="pe",
            origins="cnet;softonic",
            flags="any_softonic",
        ),
        _row(
            SHA_UNINV,
            f"malware/_unlabelled/vault_bb/{SHA_UNINV}.bin",
            folder="malware/_unlabelled/vault_bb",
            pool="malware",
            kind="uninventoried",
            origins="vault_bb",
            flags="oversized_uninventoried",
        ),
        _row(
            SHA_CHILD,
            f"goodware/selfpacked_upx/{SHA_CHILD}.bin",
            folder="goodware/selfpacked_upx",
            pool="goodware",
            kind="pe",
            origins="selfpacked_upx",
            flags="selfpacked_child",
            parent_sha256=SHA_GOOD,
        ),
    ]
    root.mkdir()
    (root / "metadata").mkdir()
    for r in rows:
        f = root / r["dataset_path"]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x")
    csv_path = root / "metadata" / "sherlock_manifest.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    db_path = tmp_path / "work" / "manifest" / "manifest.sqlite"
    db_path.parent.mkdir(parents=True)
    con = sqlite3.connect(db_path)
    con.executescript(
        """
        CREATE TABLE files (sha256 TEXT PRIMARY KEY, md5 TEXT, sha1 TEXT,
            tlsh TEXT, size INTEGER, pool TEXT, kind TEXT, magic TEXT,
            magika_label TEXT, first_seen_local TEXT);
        CREATE TABLE file_paths (path TEXT PRIMARY KEY, sha256 TEXT, origin TEXT,
            size INTEGER, mtime REAL);
        CREATE TABLE packer_tags (sha256 TEXT, tool TEXT, packed INTEGER,
            packer_name TEXT, confidence REAL, evidence TEXT);
        CREATE TABLE packed_from (parent_sha256 TEXT, child_sha256 TEXT,
            packer TEXT, packer_version TEXT, args TEXT);
        CREATE TABLE runs (run_id INTEGER, command TEXT);
        """
    )
    for sha, pool in (
        (SHA_PE, "malware"),
        (SHA_GOOD, "goodware"),
        (SHA_CHILD, "goodware"),
        (SHA_DB_ONLY, "malware"),
    ):
        con.execute(
            "INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sha, "m", "s", None, 10, pool, "pe", "PE32", None, "2026-10-01"),
        )
        con.execute(
            "INSERT INTO file_paths VALUES (?,?,?,?,?)",
            (f"/dead/old/cluster/{sha}", sha, "x", 10, 0.0),
        )
    con.executemany(
        "INSERT INTO packer_tags VALUES (?,?,?,?,?,?)",
        [
            (SHA_PE, "die", 1, "UPX", 1.0, "e"),
            (SHA_PE, "yara", 1, "UPX", 0.5, "e"),
        ],
    )
    con.execute(
        "INSERT INTO packed_from VALUES (?,?,?,?,?)",
        (SHA_GOOD, SHA_CHILD, "upx", "4.2", "-9"),
    )
    con.commit()
    con.close()
    return FakeDataset(root=root, csv_path=csv_path, db_path=db_path)

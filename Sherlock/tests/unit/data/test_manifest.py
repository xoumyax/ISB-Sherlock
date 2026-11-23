"""Unit tests for ``sherlock.data.manifest`` on the tiny fake dataset (conftest)."""

from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

import pytest

from sherlock.data.manifest import (
    BARRED_COLUMNS,
    DBJoin,
    LeakageError,
    Manifest,
    ManifestDB,
    ManifestRow,
    Resolution,
    Split,
    require_training_families,
)
from sherlock.data.roots import Roots

from .conftest import (
    COLUMNS,
    SHA_CHILD,
    SHA_DB_ONLY,
    SHA_GOOD,
    SHA_PE,
    SHA_UNINV,
    FakeDataset,
)

# -- CSV: sha256 -> path and metadata -----------------------------------------


def test_load_and_lookup(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    assert len(m) == 4
    assert SHA_PE in m and SHA_DB_ONLY not in m
    row = m.row(SHA_PE)
    assert isinstance(row, ManifestRow)
    assert row.pool == "malware" and row.kind == "pe"
    assert row.size == 10 and row.n_paths == 1
    assert row.origins == ("bazaar_run4", "vault_bb")
    assert row.flags == ()
    assert row.mb_family == "agenttesla"
    assert row.mb_first_seen == "2024-01-02 03:04:05"
    assert row.die_packed is True and row.die_packer == "UPX"
    assert row.motif_family is None  # empty cells are None, not ""
    assert m.row(SHA_GOOD).flags == ("any_softonic",)
    assert m.row(SHA_GOOD).die_packed is None
    assert m.row(SHA_CHILD).parent_sha256 == SHA_GOOD


def test_path_resolves_under_dataset_root(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    p = m.path(SHA_PE)
    assert p == fake_dataset.root / "malware" / "agenttesla" / f"{SHA_PE}.bin"
    assert p.is_file()


def test_unknown_hash_raises_key_error(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    with pytest.raises(KeyError, match="not in sherlock_manifest.csv"):
        m.path(SHA_DB_ONLY)


def test_resolve_many_records_drops(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    (fake_dataset.root / m.row(SHA_GOOD).dataset_path).unlink()
    res = m.resolve_many([SHA_PE, SHA_DB_ONLY, SHA_GOOD], check_exists=True)
    assert list(res.paths) == [SHA_PE]
    assert res.dropped == {"not_in_manifest": [SHA_DB_ONLY], "missing_file": [SHA_GOOD]}
    assert res.summary() == {
        "n_requested": 3,
        "n_resolved": 1,
        "dropped": {"not_in_manifest": 1, "missing_file": 1},
    }
    assert not res  # truthy only when nothing was dropped


def test_select_by_pool_kind_flag(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    assert m.shas(pool="goodware") == sorted([SHA_GOOD, SHA_CHILD])
    assert m.shas(kind="uninventoried") == [SHA_UNINV]
    assert m.shas(flag="any_softonic") == [SHA_GOOD]
    assert m.shas() == sorted([SHA_PE, SHA_GOOD, SHA_UNINV, SHA_CHILD])


def _rewrite(csv_path: Path, sha: str, **kw: str) -> None:
    rows = list(csv.DictReader(csv_path.open()))
    for r in rows:
        if r["sha256"] == sha:
            r.update(kw)
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)


@pytest.mark.parametrize("bad", [f"/abs/{SHA_PE}.bin", f"malware/../../{SHA_PE}.bin"])
def test_unsafe_dataset_path_rejected(fake_dataset: FakeDataset, bad: str) -> None:
    _rewrite(fake_dataset.csv_path, SHA_PE, dataset_path=bad)
    with pytest.raises(ValueError, match="must be relative"):
        Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)


def test_path_name_must_match_hash(fake_dataset: FakeDataset) -> None:
    _rewrite(fake_dataset.csv_path, SHA_PE, dataset_path="malware/x/other.bin")
    with pytest.raises(ValueError, match="sha256"):
        Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)


def test_duplicate_hash_rejected(fake_dataset: FakeDataset) -> None:
    with fake_dataset.csv_path.open("a", newline="") as fh:
        fh.write(fake_dataset.csv_path.read_text().splitlines()[1] + "\n")
    with pytest.raises(ValueError, match="duplicate"):
        Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)


def test_missing_column_rejected(tmp_path: Path) -> None:
    p = tmp_path / "m.csv"
    p.write_text("sha256,dataset_path\n")
    with pytest.raises(ValueError, match="columns"):
        Manifest.from_csv(p, tmp_path)


def test_load_from_roots(fake_dataset: FakeDataset, tmp_path: Path) -> None:
    roots = Roots(
        dataset=fake_dataset.root, work=tmp_path / "w", scratch=tmp_path / "s"
    )
    assert len(Manifest.load(roots)) == 4


# -- DB: read-only, CSV-driven joins --------------------------------------------


def test_db_is_read_only(fake_dataset: FakeDataset) -> None:
    with ManifestDB(fake_dataset.db_path) as db:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db._con.execute("DELETE FROM files")


def test_db_missing_file_says_how_to_fix(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="CHECKPOINT"):
        ManifestDB(tmp_path / "nope.sqlite")


def test_fetch_drives_from_csv_and_records_missing(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    with ManifestDB(fake_dataset.db_path) as db:
        j = db.fetch("files", m.shas(), columns=("pool", "kind"))
    assert set(j.rows) == {SHA_PE, SHA_GOOD, SHA_CHILD}
    assert j.rows[SHA_PE] == [{"sha256": SHA_PE, "pool": "malware", "kind": "pe"}]
    assert j.dropped == {"no_db_row": [SHA_UNINV]}
    assert SHA_DB_ONLY not in j.rows  # never asked for: the CSV drives


def test_fetch_many_rows_per_hash(fake_dataset: FakeDataset) -> None:
    with ManifestDB(fake_dataset.db_path) as db:
        j = db.fetch("packer_tags", [SHA_PE], columns=("tool",))
    assert [r["tool"] for r in j.rows[SHA_PE]] == ["die", "yara"]


def test_fetch_other_key_column(fake_dataset: FakeDataset) -> None:
    with ManifestDB(fake_dataset.db_path) as db:
        j = db.fetch("packed_from", [SHA_CHILD], key="child_sha256")
    assert j.rows[SHA_CHILD][0]["parent_sha256"] == SHA_GOOD


def test_default_columns_exclude_barred(fake_dataset: FakeDataset) -> None:
    with ManifestDB(fake_dataset.db_path) as db:
        j = db.fetch("files", [SHA_PE])
        assert "first_seen_local" not in j.rows[SHA_PE][0]
        assert "first_seen_local" not in db.columns("files")
        j2 = db.fetch("file_paths", [SHA_PE])
        assert "path" not in j2.rows[SHA_PE][0]
        assert j2.rows[SHA_PE][0]["origin"] == "x"


@pytest.mark.parametrize(
    "table,column",
    [("files", "first_seen_local"), ("file_paths", "path")],
)
def test_barred_column_raises(
    fake_dataset: FakeDataset, table: str, column: str
) -> None:
    assert (table, column) in BARRED_COLUMNS
    with (
        ManifestDB(fake_dataset.db_path) as db,
        pytest.raises(ValueError, match=column),
    ):
        db.fetch(table, [SHA_PE], columns=(column,))


def test_unknown_table_or_column_or_key_raises(fake_dataset: FakeDataset) -> None:
    with ManifestDB(fake_dataset.db_path) as db:
        with pytest.raises(ValueError, match="no table"):
            db.fetch("nope", [SHA_PE])
        with pytest.raises(ValueError, match="no column"):
            db.fetch("files", [SHA_PE], columns=("nope",))
        with pytest.raises(ValueError, match="key"):
            db.fetch("runs", [SHA_PE])


def test_hashes_in_table(fake_dataset: FakeDataset) -> None:
    with ManifestDB(fake_dataset.db_path) as db:
        assert db.hashes("files") == {SHA_PE, SHA_GOOD, SHA_CHILD, SHA_DB_ONLY}


def test_fetch_chunks_large_requests(fake_dataset: FakeDataset) -> None:
    many = [f"{i:064x}" for i in range(2500)] + [SHA_PE]
    with ManifestDB(fake_dataset.db_path) as db:
        j = db.fetch("files", many, columns=("kind",))
    assert list(j.rows) == [SHA_PE]
    assert len(j.dropped["no_db_row"]) == 2500


# -- leakage guard (API at G0, split data at G1) ------------------------------


def test_split_round_trip_and_validation() -> None:
    s = Split.from_dict({"fam_a": "F_train", "fam_b": "F_dev", "fam_c": "F_test"})
    assert s.families("F_train") == ["fam_a"]
    assert Split.from_dict(s.to_dict()).to_dict() == s.to_dict()
    with pytest.raises(ValueError, match="F_holdout"):
        Split.from_dict({"fam_a": "F_holdout"})


def test_split_load_not_built_until_g1(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError, match="G1"):
        Split.load(tmp_path / "malware_split.json")


def test_training_families_pass() -> None:
    s = Split.from_dict({"b": "F_train", "a": "F_train", "c": "F_test"})
    assert require_training_families(["b", "a"], s, purpose="labels") == ["a", "b"]


def test_leakage_error_is_value_error() -> None:
    assert issubclass(LeakageError, ValueError)


# -- review fixes (session 2) -------------------------------------------------


@pytest.mark.parametrize("col,val", [("size", ""), ("n_paths", "1e3")])
def test_bad_int_cell_raises_with_line(
    fake_dataset: FakeDataset, col: str, val: str
) -> None:
    _rewrite(fake_dataset.csv_path, SHA_PE, **{col: val})
    with pytest.raises(ValueError, match=rf"line \d+: {col}"):
        Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)


def test_short_row_raises_with_line(fake_dataset: FakeDataset) -> None:
    with fake_dataset.csv_path.open("a") as fh:
        fh.write(f"{'6' * 64},malware/x/{'6' * 64}.bin\n")
    with pytest.raises(ValueError, match=r"line 6: .*columns"):
        Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)


def test_open_writes_no_sidecar_files(tmp_path: Path) -> None:
    # A mode=ro open of a WAL database still creates -shm/-wal files when the
    # directory is writable (review finding, 23 Nov); immutable=1 doesn't.
    db = tmp_path / "wal" / "m.sqlite"
    db.parent.mkdir()
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE files (sha256 TEXT, kind TEXT)")
    con.execute("INSERT INTO files VALUES (?, 'pe')", (SHA_PE,))
    con.commit()
    con.close()
    for side in ("-wal", "-shm"):
        Path(f"{db}{side}").unlink(missing_ok=True)
    before = sorted(p.name for p in db.parent.iterdir())
    with ManifestDB(db) as mdb:
        assert mdb.fetch("files", [SHA_PE]).rows[SHA_PE][0]["kind"] == "pe"
    assert sorted(p.name for p in db.parent.iterdir()) == before


def test_coverage_records_both_sides(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    with ManifestDB(fake_dataset.db_path) as db:
        cov = db.coverage(m)
    assert cov.csv_only == [SHA_UNINV]
    assert cov.db_only == [SHA_DB_ONLY]
    assert cov.summary() == {"table": "files", "n_csv_only": 1, "n_db_only": 1}
    assert type(cov).from_dict(cov.to_dict()) == cov


@pytest.mark.parametrize(
    "table,column",
    [
        ("pe_meta", "timestamp"),
        ("file_paths", "mtime"),
        ("archive_extractions", "extracted_at"),
        ("errors", "subject"),
    ],
)
def test_other_trap_columns_barred(table: str, column: str) -> None:
    assert (table, column) in BARRED_COLUMNS


def test_results_round_trip(fake_dataset: FakeDataset) -> None:
    m = Manifest.from_csv(fake_dataset.csv_path, fake_dataset.root)
    res = m.resolve_many([SHA_PE, SHA_DB_ONLY])
    assert Resolution.from_dict(res.to_dict(), m).to_dict() == res.to_dict()
    assert str(fake_dataset.root) not in str(res.to_dict())  # H7: hashes only
    with ManifestDB(fake_dataset.db_path) as db:
        j = db.fetch("files", m.shas(), columns=("kind",))
    assert DBJoin.from_dict(j.to_dict()).to_dict() == j.to_dict()


def test_split_is_immutable_and_hashable() -> None:
    src = {"a": "F_train"}
    s = Split.from_dict(src)
    src["a"] = "F_test"
    assert require_training_families(["a"], s, purpose="x") == ["a"]
    assert hash(s) == hash(Split.from_dict({"a": "F_train"}))


def test_open_refuses_unmerged_wal(tmp_path: Path) -> None:
    # immutable=1 ignores the -wal file, so frames a writer left there would be
    # silently invisible: refuse instead (G0 review follow-up).
    db = tmp_path / "wal2" / "m.sqlite"
    db.parent.mkdir()
    writer = sqlite3.connect(db)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE files (sha256 TEXT)")
    writer.commit()
    writer.execute("INSERT INTO files VALUES ('x')")
    writer.commit()
    try:
        assert Path(f"{db}-wal").stat().st_size > 0
        with pytest.raises(ValueError, match="checkpoint"):
            ManifestDB(db)
    finally:
        writer.close()


@pytest.mark.parametrize(
    "table,column",
    [
        ("pe_meta", "timestamp"),
        ("file_paths", "mtime"),
        ("archive_extractions", "extracted_at"),
        ("errors", "subject"),
    ],
)
def test_trap_columns_cannot_be_fetched(
    tmp_path: Path, table: str, column: str
) -> None:
    db = tmp_path / "trap.sqlite"
    con = sqlite3.connect(db)
    key = "parent_sha256" if table == "archive_extractions" else "sha256"
    con.execute(f'CREATE TABLE "{table}" ("{key}" TEXT, "{column}" TEXT, k TEXT)')
    con.execute(f'INSERT INTO "{table}" VALUES (?, ?, ?)', (SHA_PE, "t", "v"))
    con.commit()
    con.close()
    with ManifestDB(db) as mdb:
        with pytest.raises(ValueError, match=column):
            mdb.fetch(table, [SHA_PE], columns=(column,), key=key)
        assert column not in mdb.fetch(table, [SHA_PE], key=key).rows[SHA_PE][0]
        assert column not in mdb.columns(table)


@pytest.mark.parametrize("bad", ["ab", [("a", "F_train", "x")]])
def test_split_bad_shape_is_value_error(bad: object) -> None:
    with pytest.raises(ValueError, match="Split"):
        Split(assignment=bad)  # type: ignore[arg-type]

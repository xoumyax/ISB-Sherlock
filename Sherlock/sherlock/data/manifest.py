"""The sample manifest: sha256 -> file and metadata, the working DB, leakage guards.

Three sources, three rules:

``metadata/sherlock_manifest.csv`` (under ``ISB_DATA``) **drives everything.**
    One row per sample (117,999 on ramius, accepted 2026-11-23,
    ``docs/migration/ACCEPTANCE.md``). A file is reached only through its
    ``dataset_path``, relative to the dataset root, so no artifact holds an
    absolute path (H7). Loading checks that every path is relative, stays inside
    the root and is named ``<sha256>.bin``.

``ISB_WORK/manifest/manifest.sqlite`` is **joined on sha256, read-only.**
    It is the working copy of the run-278 checkpoint (its sha256 is in
    ``CHECKPOINT.sha256``) and covers a different set of hashes: 85 CSV hashes
    have no ``files`` row (the ``oversized_uninventoried`` files, never
    inventoried) and 30 DB hashes have no CSV row (MalwareBazaar export files run
    278 counted as malware). So a join starts from the CSV's hashes and a missing
    DB row is a recorded condition, ``dropped["no_db_row"]``, never an error.
    Some columns can't be read at all (:data:`BARRED_COLUMNS`): ``file_paths.path``
    (dead old-cluster paths, 133,664 rows) and the inventory and compile times that
    could pass for sample dates, starting with ``files.first_seen_local`` (H6).
    Reads name their columns; there is no ``SELECT *``. The file is opened
    ``mode=ro&immutable=1``: ``mode=ro`` alone still writes ``-shm``/``-wal``
    beside a WAL database (G0 review, 2026-11-23). An immutable read ignores the
    ``-wal`` file, so a non-empty one is refused rather than read around.

**Leakage guards raise** (lesson L12). ``require_training_families`` has no
    off-switch: it raises unless every family is placed in F_train. Until the split
    is frozen at G1 there is no split to load, so it raises for every family.
"""

from __future__ import annotations

import csv
import re
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, fields
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Any

from .roots import Roots

__all__ = [
    "MANIFEST_CSV",
    "MANIFEST_DB",
    "BARRED_COLUMNS",
    "SPLIT_NAMES",
    "ManifestRow",
    "Resolution",
    "Manifest",
    "DBJoin",
    "Coverage",
    "ManifestDB",
    "LeakageError",
    "Split",
    "require_training_families",
]

#: The manifest CSV, relative to the dataset root.
MANIFEST_CSV = PurePosixPath("metadata/sherlock_manifest.csv")
#: The working DB, relative to the work root.
MANIFEST_DB = PurePosixPath("manifest/manifest.sqlite")

#: (table, column) pairs no Sherlock code may read, and why.
BARRED_COLUMNS: Mapping[tuple[str, str], str] = {
    ("file_paths", "path"): "dead old-cluster paths; resolve through dataset_path",
    ("files", "first_seen_local"): "inventory time, not a sample date (H6)",
    ("pe_meta", "timestamp"): (
        "compile timestamp, forgeable; never a sample date (H6). Unbar by decision "
        "if a feature needs it"
    ),
    ("file_paths", "mtime"): "old-cluster file time, not a sample date (H6)",
    ("archive_extractions", "extracted_at"): "inventory time, not a sample date (H6)",
    ("errors", "subject"): "holds dead old-cluster paths as well as hashes",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
#: SQLite's default limit on bound parameters is 999 on older builds.
_CHUNK = 900


# -- CSV rows -----------------------------------------------------------------


@dataclass(frozen=True)
class ManifestRow:
    """One row of ``sherlock_manifest.csv``. Empty cells are ``None``."""

    sha256: str
    dataset_path: str
    folder: str
    folder_basis: str | None
    pool: str
    kind: str
    size: int
    md5: str | None
    sha1: str | None
    tlsh: str | None
    mb_family: str | None
    mb_family_raw: str | None
    #: Source date from MalwareBazaar; never replaced by inventory time (H6).
    mb_first_seen: str | None
    mb_label_source: str | None
    motif_family: str | None
    motif_family_raw: str | None
    motif_tier: str | None
    die_packed: bool | None
    die_packer: str | None
    #: ``;``-separated in the CSV.
    origins: tuple[str, ...]
    n_paths: int
    #: ``;``-separated in the CSV (``any_softonic``, ``archive_member``, ...).
    flags: tuple[str, ...]
    parent_sha256: str | None
    v1_crosscheck: str | None

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


_ROW_COLUMNS: tuple[str, ...] = tuple(f.name for f in fields(ManifestRow))
_LIST_COLUMNS = frozenset({"origins", "flags"})
_INT_COLUMNS = frozenset({"size", "n_paths"})


def _parse_bool(raw: str) -> bool | None:
    if raw == "":
        return None
    if raw in ("1", "true", "True"):
        return True
    if raw in ("0", "false", "False"):
        return False
    raise ValueError(f"die_packed must be 1, 0 or empty, got {raw!r}")


def _parse_row(raw: Mapping[str, str], lineno: int) -> ManifestRow:
    if None in raw or any(raw[c] is None for c in _ROW_COLUMNS):
        n = sum(1 for k, v in raw.items() if k is not None and v is not None)
        raise ValueError(
            f"line {lineno}: row has the wrong number of columns ({n} filled, "
            f"{len(_ROW_COLUMNS)} expected)"
        )
    values: dict[str, Any] = {}
    for col in _ROW_COLUMNS:
        cell = raw[col]
        if col in _LIST_COLUMNS:
            values[col] = tuple(x for x in cell.split(";") if x)
        elif col in _INT_COLUMNS:
            try:
                values[col] = int(cell)
            except ValueError:
                raise ValueError(
                    f"line {lineno}: {col} must be an integer, got {cell!r}"
                ) from None
        elif col == "die_packed":
            values[col] = _parse_bool(cell)
        else:
            values[col] = cell if cell != "" else None
    row = ManifestRow(**values)
    if not _SHA256.match(row.sha256):
        raise ValueError(f"line {lineno}: bad sha256 {row.sha256!r}")
    _check_dataset_path(row.dataset_path, row.sha256, lineno)
    return row


def _check_dataset_path(path: str | None, sha: str, lineno: int) -> None:
    if not path:
        raise ValueError(f"line {lineno}: empty dataset_path for {sha}")
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(
            f"line {lineno}: dataset_path {path!r} must be relative to the dataset "
            "root and stay inside it"
        )
    if p.name != f"{sha}.bin":
        raise ValueError(
            f"line {lineno}: dataset_path {path!r} is not named after its sha256"
        )


# -- CSV manifest -------------------------------------------------------------


@dataclass
class Resolution:
    """Paths for the hashes that resolved, and the rest by reason."""

    paths: dict[str, Path] = field(default_factory=dict)
    dropped: dict[str, list[str]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return not self.dropped

    def to_dict(self) -> dict[str, Any]:
        """Hashes only, never absolute paths (H7): paths are rebuilt from the
        manifest by :meth:`from_dict`."""
        return {
            "resolved": list(self.paths),
            "dropped": {k: list(v) for k, v in self.dropped.items()},
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any], manifest: Manifest) -> Resolution:
        return cls(
            paths={s: manifest.path(s) for s in d["resolved"]},
            dropped={k: list(v) for k, v in d["dropped"].items()},
        )

    def summary(self) -> dict[str, Any]:
        n_dropped = sum(len(v) for v in self.dropped.values())
        return {
            "n_requested": len(self.paths) + n_dropped,
            "n_resolved": len(self.paths),
            "dropped": {k: len(v) for k, v in self.dropped.items()},
        }


class Manifest:
    """``sherlock_manifest.csv`` in memory, keyed by sha256."""

    def __init__(self, rows: Mapping[str, ManifestRow], dataset_root: Path) -> None:
        self._rows = dict(rows)
        self.dataset_root = dataset_root

    @classmethod
    def from_csv(cls, csv_path: Path, dataset_root: Path) -> Manifest:
        rows: dict[str, ManifestRow] = {}
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            missing = sorted(set(_ROW_COLUMNS) - set(reader.fieldnames or ()))
            if missing:
                raise ValueError(f"{csv_path} is missing columns {missing}")
            for lineno, raw in enumerate(reader, start=2):
                row = _parse_row(raw, lineno)
                if row.sha256 in rows:
                    raise ValueError(f"line {lineno}: duplicate sha256 {row.sha256}")
                rows[row.sha256] = row
        return cls(rows, dataset_root)

    @classmethod
    def load(cls, roots: Roots) -> Manifest:
        """The manifest under ``roots.dataset``."""
        return cls.from_csv(roots.dataset / MANIFEST_CSV, roots.dataset)

    def __len__(self) -> int:
        return len(self._rows)

    def __contains__(self, sha256: object) -> bool:
        return sha256 in self._rows

    def __iter__(self) -> Iterator[str]:
        return iter(self._rows)

    def row(self, sha256: str) -> ManifestRow:
        try:
            return self._rows[sha256]
        except KeyError:
            raise KeyError(f"{sha256} not in sherlock_manifest.csv") from None

    def path(self, sha256: str) -> Path:
        """Absolute path of the sample file, built from ``dataset_path``."""
        return self.dataset_root / self.row(sha256).dataset_path

    def resolve_many(
        self, shas: Iterable[str], *, check_exists: bool = False
    ) -> Resolution:
        """Resolve many hashes; unknown or missing ones are dropped by reason."""
        res = Resolution()
        for sha in dict.fromkeys(shas):
            if sha not in self._rows:
                res.dropped.setdefault("not_in_manifest", []).append(sha)
                continue
            p = self.path(sha)
            if check_exists and not p.is_file():
                res.dropped.setdefault("missing_file", []).append(sha)
                continue
            res.paths[sha] = p
        return res

    def shas(
        self,
        *,
        pool: str | None = None,
        kind: str | None = None,
        flag: str | None = None,
    ) -> list[str]:
        """Sorted hashes matching every filter given."""
        return sorted(
            sha
            for sha, r in self._rows.items()
            if (pool is None or r.pool == pool)
            and (kind is None or r.kind == kind)
            and (flag is None or flag in r.flags)
        )


# -- working DB ---------------------------------------------------------------


@dataclass
class DBJoin:
    """Rows of one table for the requested hashes, in request order."""

    table: str
    key: str
    rows: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    dropped: dict[str, list[str]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return not self.dropped

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "key": self.key,
            "rows": {k: [dict(r) for r in v] for k, v in self.rows.items()},
            "dropped": {k: list(v) for k, v in self.dropped.items()},
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> DBJoin:
        return cls(
            table=d["table"],
            key=d["key"],
            rows={k: [dict(r) for r in v] for k, v in d["rows"].items()},
            dropped={k: list(v) for k, v in d["dropped"].items()},
        )

    def summary(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "key": self.key,
            "n_matched": len(self.rows),
            "n_rows": sum(len(v) for v in self.rows.values()),
            "dropped": {k: len(v) for k, v in self.dropped.items()},
        }


@dataclass(frozen=True)
class Coverage:
    """Which hashes the CSV and one DB table don't share, both sorted.

    Measured 2026-11-23 on ``files``: 85 CSV-only (``oversized_uninventoried``) and
    30 DB-only (MalwareBazaar export files). Both are recorded conditions.
    """

    table: str
    csv_only: list[str]
    db_only: list[str]

    def summary(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "n_csv_only": len(self.csv_only),
            "n_db_only": len(self.db_only),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "csv_only": list(self.csv_only),
            "db_only": list(self.db_only),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Coverage:
        return cls(
            table=d["table"], csv_only=list(d["csv_only"]), db_only=list(d["db_only"])
        )


class ManifestDB:
    """Read-only access to the working ``manifest.sqlite``, joined on sha256."""

    def __init__(self, path: Path) -> None:
        if not path.is_file():
            raise ValueError(
                f"{path} not found: copy the checkpoint manifest.sqlite from "
                "ISB_DATA/metadata/project_state/ISB-Corpus-Update/data/ to "
                "ISB_WORK/manifest/ and check it against CHECKPOINT.sha256"
            )
        wal = Path(f"{path}-wal")
        if wal.is_file() and wal.stat().st_size > 0:
            raise ValueError(
                f"{wal} holds unmerged writes that an immutable read would not see; "
                "checkpoint the DB first (the writer closes cleanly, or run PRAGMA "
                "wal_checkpoint(TRUNCATE) from the job that owns it)"
            )
        self.path = path
        # immutable=1 as well as mode=ro: a read-only open of a WAL database still
        # creates or updates its -shm/-wal files when the directory is writable
        # (found in the G0 review, 2026-11-23). Nothing may write beside the DB,
        # and never under ISB_DATA. The cost: no locking, so don't read while an
        # enrichment job is writing the same file.
        uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
        self._con = sqlite3.connect(uri, uri=True)
        self._columns: dict[str, list[str]] = {}
        try:
            for (name,) in self._con.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ):
                info = self._con.execute(f'PRAGMA table_info("{name}")')
                self._columns[name] = [r[1] for r in info]
        except sqlite3.Error:
            self._con.close()
            raise

    @classmethod
    def open(cls, roots: Roots) -> ManifestDB:
        return cls(roots.work / MANIFEST_DB)

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> ManifestDB:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- schema --------------------------------------------------------------
    def tables(self) -> list[str]:
        return sorted(self._columns)

    def columns(self, table: str) -> list[str]:
        """Readable columns of ``table``: every column except the barred ones."""
        self._check_table(table)
        return [c for c in self._columns[table] if (table, c) not in BARRED_COLUMNS]

    def _check_table(self, table: str) -> None:
        if table not in self._columns:
            raise ValueError(f"no table {table!r}; tables: {self.tables()}")

    def _check_column(self, table: str, column: str) -> None:
        if column not in self._columns[table]:
            raise ValueError(f"no column {column!r} in {table}")
        why = BARRED_COLUMNS.get((table, column))
        if why is not None:
            raise ValueError(f"{table}.{column} may not be read: {why}")

    # -- reads ---------------------------------------------------------------
    def fetch(
        self,
        table: str,
        shas: Iterable[str],
        columns: Sequence[str] | None = None,
        *,
        key: str = "sha256",
    ) -> DBJoin:
        """Rows of ``table`` whose ``key`` is one of ``shas``.

        Every hash with no row is recorded under ``dropped["no_db_row"]``. A table
        may hold several rows per hash (``packer_tags``), so each maps to a list,
        in table order.
        """
        self._check_table(table)
        if "sha256" not in key:
            raise ValueError(f"key {key!r} must be a sha256 column")
        if key not in self._columns[table]:
            raise ValueError(f"{table} has no key column {key!r}; pass key=")
        cols = list(columns) if columns is not None else self.columns(table)
        for c in cols:
            self._check_column(table, c)
        select = [key] + [c for c in cols if c != key]
        for name in select:
            if not _IDENT.match(name):
                raise ValueError(f"bad column name {name!r}")
        wanted = list(dict.fromkeys(shas))
        found: dict[str, list[dict[str, Any]]] = {}
        col_sql = ", ".join(f'"{c}"' for c in select)
        for i in range(0, len(wanted), _CHUNK):
            chunk = wanted[i : i + _CHUNK]
            marks = ",".join("?" * len(chunk))
            sql = (
                f'SELECT {col_sql} FROM "{table}" WHERE "{key}" IN ({marks}) '
                "ORDER BY rowid"
            )
            for rec in self._con.execute(sql, chunk):
                found.setdefault(rec[0], []).append(dict(zip(select, rec, strict=True)))
        join = DBJoin(table=table, key=key)
        for sha in wanted:
            if sha in found:
                join.rows[sha] = found[sha]
            else:
                join.dropped.setdefault("no_db_row", []).append(sha)
        return join

    def coverage(self, manifest: Manifest, table: str = "files") -> Coverage:
        """Hashes only in the CSV and only in ``table``: both recorded, neither an
        error. Joins still start from the CSV's hashes."""
        in_db = self.hashes(table)
        in_csv = set(manifest)
        return Coverage(
            table=table,
            csv_only=sorted(in_csv - in_db),
            db_only=sorted(in_db - in_csv),
        )

    def hashes(self, table: str, key: str = "sha256") -> set[str]:
        """Every distinct ``key`` value in ``table``."""
        self._check_table(table)
        self._check_column(table, key)
        return {
            r[0] for r in self._con.execute(f'SELECT DISTINCT "{key}" FROM "{table}"')
        }


# -- leakage guard ------------------------------------------------------------

SPLIT_NAMES: tuple[str, ...] = ("F_train", "F_dev", "F_test")


class LeakageError(ValueError):
    """A family outside F_train reached code that may only see F_train (L12)."""


@dataclass(frozen=True)
class Split:
    """Family -> split assignment over alias groups. Frozen at G1.

    Stored as a sorted tuple of pairs, so a split can't change after it is built
    (a shared dict could be mutated behind the guard's back) and is hashable.
    """

    assignment: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        items: Any = self.assignment
        if isinstance(items, Mapping):
            items = tuple(items.items())
        if isinstance(items, str | bytes) or not all(
            isinstance(p, tuple | list)
            and len(p) == 2
            and all(isinstance(x, str) for x in p)
            for p in items
        ):
            raise ValueError(
                "Split.assignment must map family -> split name; build it with "
                "Split.from_dict({family: 'F_train', ...})"
            )
        object.__setattr__(self, "assignment", tuple(sorted(tuple(p) for p in items)))
        fams = [f for f, _ in self.assignment]
        if len(set(fams)) != len(fams):
            raise ValueError("a family may appear in only one split")
        bad = sorted({s for _, s in self.assignment if s not in SPLIT_NAMES})
        if bad:
            raise ValueError(f"unknown split names {bad}; allowed: {SPLIT_NAMES}")

    @classmethod
    def from_dict(cls, d: Mapping[str, str]) -> Split:
        return cls(assignment=tuple(d.items()))

    def to_dict(self) -> dict[str, str]:
        return dict(self.assignment)

    def get(self, family: str) -> str | None:
        """The split ``family`` is in, or ``None`` if it isn't placed."""
        return dict(self.assignment).get(family)

    def families(self, name: str) -> list[str]:
        """Sorted families placed in split ``name``."""
        return [f for f, s in self.assignment if s == name]

    @classmethod
    def load(cls, path: Path) -> Split:
        """Load ``ISB_WORK/splits/malware_split.json``: its format is fixed at G1."""
        raise NotImplementedError(
            f"cannot load {path.name}: the split and its file format are frozen at "
            "G1; build a Split with Split.from_dict until then"
        )


def require_training_families(
    families: Iterable[str], split: Split | None, purpose: str
) -> list[str]:
    """Return ``families`` sorted if every one is in F_train; raise otherwise.

    There is no off-switch. With no split loaded (before G1) every call raises.
    """
    fams = sorted(set(families))
    if split is None:
        raise LeakageError(
            f"{purpose}: no split loaded, so no family is known to be F_train; the "
            "split is frozen at G1"
        )
    bad = {f: split.get(f) or "unplaced" for f in fams}
    bad = {f: s for f, s in bad.items() if s != "F_train"}
    if bad:
        raise LeakageError(
            f"{purpose} may only use F_train families; got {dict(sorted(bad.items()))}"
        )
    return fams

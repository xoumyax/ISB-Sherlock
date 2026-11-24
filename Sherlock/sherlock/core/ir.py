"""The Candidate IR: one observation about a binary that a YARA rule can test.

Designed from first principles on 2026-11-23 (``docs/gates/G0.md`` §2a), after
brownie's decision that Sherlock is not influenced by V1: no V1 code was consulted.

YARA tests a file in two ways, and the kinds follow them. Byte-level kinds
(``TEXT``, ``BYTES``) become strings matched anywhere in the file; structural kinds
(``PE_IMPORT``, ``PE_SECTION_NAME``, ``PE_IMPHASH``) become ``pe`` module terms. The
set is small and provisional: each extractor added in P3 brings its kinds, and each
kind states its render and match forms against YARA's semantics.

Two forms, kept apart (lesson L1, ``tests/lessons/test_l01_render_form.py``):

**Render form**: ``value`` and ``qualifier``, exactly as observed. This is what a
    rule writer puts in the rule, so it must match the sample.
**Match form**: ``match_key()``, derived and never stored or rendered. It equals the
    render form except where YARA itself ignores a difference: a ``PE_IMPORT``'s DLL
    name is lower-cased because YARA compares DLL names case-insensitively (to be
    pinned by a grammar test against the YARA docs in P3). Text is never case-folded:
    YARA text strings are case-sensitive unless ``nocase``, and choosing ``nocase``
    is a selection decision, not an observation. (The lesson, measured in V1:
    rendering a folded form writes rules that can't match their own sample.)

Observations are concrete: no wildcards, jumps or alternations, which are rule
decisions (grammar, P3). Construction is strict: Sherlock's own extractors are the
only producers, so a bad kind or value is a bug and raises ``ValueError``. Reading
JSONL is forgiving: a bad line is dropped by reason with its line number.

Every candidate keeps its **occurrences** ``(sha256, section, offset)``, so analyst
rule hits (W4), spans and strings align by file offset, and support can be counted
over TLSH clusters (W1) rather than files.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "Kind",
    "KINDS",
    "ENCODINGS",
    "Occurrence",
    "Candidate",
    "write_candidates_jsonl",
    "read_candidates_jsonl",
]


# -- kinds --------------------------------------------------------------------


class Kind:
    """Candidate kinds: plain string constants, so JSONL needs no conversion."""

    #: Characters found in the file; ``encoding`` says how they are stored.
    TEXT = "TEXT"
    #: A run of concrete bytes, as lower-case hex.
    BYTES = "BYTES"
    #: A function imported by name: ``qualifier`` = DLL, ``value`` = function.
    PE_IMPORT = "PE_IMPORT"
    #: A section name from the section table.
    PE_SECTION_NAME = "PE_SECTION_NAME"
    #: The import hash, 32 lower-case hex digits (what ``pe.imphash()`` returns).
    PE_IMPHASH = "PE_IMPHASH"


KINDS: frozenset[str] = frozenset(
    {Kind.TEXT, Kind.BYTES, Kind.PE_IMPORT, Kind.PE_SECTION_NAME, Kind.PE_IMPHASH}
)

#: ``ascii``: one byte per character. ``wide``: each character followed by a zero
#: byte, which is what YARA's ``wide`` modifier matches. That is not UTF-16: YARA
#: interleaves zeros with the rule's bytes, so non-ASCII text in either encoding
#: would render a rule that misses its own sample (lesson L1). Both hold ASCII only;
#: other text is kept as ``BYTES``.
ENCODINGS: frozenset[str] = frozenset({"ascii", "wide"})

_SHA256 = re.compile(r"[0-9a-f]{64}")
_HEX = re.compile(r"(?:[0-9a-f]{2})+")
_IMPHASH = re.compile(r"[0-9a-f]{32}")
_ASCII_UPPER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_OCC_KEYS = frozenset({"sha256", "section", "offset"})
_CAND_KEYS = frozenset(
    {"kind", "value", "qualifier", "encoding", "occurrences", "source", "meta"}
)


def _check_keys(what: str, d: Any, allowed: frozenset[str]) -> None:
    if not isinstance(d, Mapping):
        raise ValueError(f"{what} record must be an object, got {d!r}")
    extra = set(d) - allowed
    if extra:
        raise ValueError(f"{what} record has unknown keys {sorted(extra)}")


# -- occurrence ---------------------------------------------------------------


@dataclass(frozen=True)
class Occurrence:
    """Where a candidate was seen: one sample, and where in it.

    ``sha256``  lower-case hex digest of the sample (the key everywhere).
    ``section`` the section name the bytes sit in, as in the header; ``None``
                outside every section (headers, overlay) or when not known.
    ``offset``  **file offset** of the first byte, from the start of the file: not
                an RVA and not section-relative, so YARA ``@s`` hits, spans and
                strings compare directly. ``None`` when the observation has no
                single location (an import, the imphash).
    """

    sha256: str
    section: str | None = None
    offset: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ValueError(
                "Occurrence.sha256 must be 64 lower-case hex chars, "
                f"got {self.sha256!r}"
            )
        if self.section is not None and not isinstance(self.section, str):
            raise ValueError(
                f"Occurrence.section must be a str or None, got {self.section!r}"
            )
        if self.offset is not None and (
            isinstance(self.offset, bool)
            or not isinstance(self.offset, int)
            or self.offset < 0
        ):
            raise ValueError(
                "Occurrence.offset must be a file offset >= 0 or None, "
                f"got {self.offset!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "section": self.section, "offset": self.offset}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Occurrence:
        """Inverse of :meth:`to_dict`; unknown keys raise ``ValueError``."""
        _check_keys("occurrence", d, _OCC_KEYS)
        return cls(sha256=d["sha256"], section=d.get("section"), offset=d.get("offset"))


# -- validation helpers -------------------------------------------------------


def _check_value(kind: str, value: str, encoding: str | None) -> None:
    if kind == Kind.BYTES:
        if not _HEX.fullmatch(value):
            raise ValueError(
                f"BYTES value must be non-empty lower-case hex, two digits per byte "
                f"(use Candidate.from_bytes), got {value!r}"
            )
        return
    if kind == Kind.PE_IMPHASH:
        if not _IMPHASH.fullmatch(value):
            raise ValueError(
                f"PE_IMPHASH value must be 32 lower-case hex digits, got {value!r}"
            )
        return
    if value == "":
        raise ValueError(f"{kind} value must not be empty")
    if kind == Kind.TEXT and not value.isascii():
        raise ValueError(
            f"{encoding} TEXT must be ASCII (YARA's wide is zero-interleaved ASCII, "
            "not UTF-16); keep other text as BYTES"
        )


def _check_meta(meta: Any) -> None:
    if not isinstance(meta, dict):
        raise ValueError(f"Candidate.meta must be a dict, got {meta!r}")
    for k, v in meta.items():
        ok = isinstance(k, str) and (
            v is None
            or isinstance(v, bool | int | str)
            or (isinstance(v, float) and math.isfinite(v))
        )
        if not ok:
            raise ValueError(
                f"Candidate.meta holds JSON scalars only (str, int, finite float, "
                f"bool, None); got {k!r}: {v!r}"
            )


# -- candidate ----------------------------------------------------------------


@dataclass(frozen=True, eq=False)
class Candidate:
    """One observation, with every place it was seen.

    Equality and hashing are on :meth:`match_key`, so the same observation in two
    samples is one candidate. Compare :meth:`to_dict` to check nothing was lost.
    """

    kind: str
    value: str
    qualifier: str | None = None
    encoding: str | None = None
    occurrences: tuple[Occurrence, ...] = ()
    #: The extractor that produced it, e.g. ``extract.pe``.
    source: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in KINDS:
            raise ValueError(f"unknown kind {self.kind!r}; kinds: {sorted(KINDS)}")
        if not isinstance(self.value, str):
            raise ValueError(f"Candidate.value must be str, got {self.value!r}")
        if self.kind == Kind.TEXT:
            if self.encoding not in ENCODINGS:
                raise ValueError(
                    f"TEXT needs an encoding in {sorted(ENCODINGS)}, "
                    f"got {self.encoding!r}"
                )
        elif self.encoding is not None:
            raise ValueError(f"only TEXT has an encoding, {self.kind} got one")
        if self.kind == Kind.PE_IMPORT:
            if not isinstance(self.qualifier, str) or not self.qualifier:
                raise ValueError("PE_IMPORT needs its DLL name as qualifier")
        elif self.qualifier is not None:
            raise ValueError(f"only PE_IMPORT has a qualifier, {self.kind} got one")
        _check_value(self.kind, self.value, self.encoding)
        occs = self.occurrences
        if isinstance(occs, str | bytes | Mapping):
            raise ValueError("Candidate.occurrences must be a sequence of Occurrence")
        try:
            occs = tuple(occs)
        except TypeError:
            raise ValueError(
                f"Candidate.occurrences must be a sequence of Occurrence, got {occs!r}"
            ) from None
        if not all(isinstance(o, Occurrence) for o in occs):
            raise ValueError("Candidate.occurrences must be a sequence of Occurrence")
        object.__setattr__(self, "occurrences", occs)
        if self.source is not None and (
            not isinstance(self.source, str) or not self.source
        ):
            raise ValueError(
                f"Candidate.source must be a non-empty str or None, got {self.source!r}"
            )
        _check_meta(self.meta)
        object.__setattr__(self, "meta", dict(self.meta))

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        occurrences: Iterable[Occurrence] = (),
        source: str | None = None,
    ) -> Candidate:
        """A ``BYTES`` candidate from raw bytes."""
        return cls(
            Kind.BYTES, data.hex(), occurrences=tuple(occurrences), source=source
        )

    # -- forms ---------------------------------------------------------------
    def match_key(self) -> tuple[str, str | None, str | None, str]:
        """``(kind, encoding, qualifier, value)`` in match form. Never rendered."""
        qualifier = self.qualifier
        if self.kind == Kind.PE_IMPORT and qualifier is not None:
            qualifier = qualifier.translate(_ASCII_UPPER)  # A-Z only, as YARA
        return (self.kind, self.encoding, qualifier, self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Candidate) and self.match_key() == other.match_key()

    def __hash__(self) -> int:
        return hash(self.match_key())

    @property
    def n_bytes(self) -> int:
        """Length of a ``BYTES`` candidate in bytes."""
        if self.kind != Kind.BYTES:
            raise ValueError(f"n_bytes is for BYTES candidates, not {self.kind}")
        return len(self.value) // 2

    def to_bytes(self) -> bytes:
        """The raw bytes of a ``BYTES`` candidate."""
        if self.kind != Kind.BYTES:
            raise ValueError(f"to_bytes is for BYTES candidates, not {self.kind}")
        return bytes.fromhex(self.value)

    # -- provenance ----------------------------------------------------------
    def with_occurrences(self, more: Iterable[Occurrence]) -> Candidate:
        """A copy with ``more`` appended; duplicates dropped, first order kept."""
        merged = tuple(dict.fromkeys((*self.occurrences, *more)))
        return Candidate(
            self.kind,
            self.value,
            qualifier=self.qualifier,
            encoding=self.encoding,
            occurrences=merged,
            source=self.source,
            meta=dict(self.meta),
        )

    def samples(self) -> tuple[str, ...]:
        """Distinct sample sha256s, in first-seen order."""
        return tuple(dict.fromkeys(o.sha256 for o in self.occurrences))

    # -- serialisation -------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Every field, as JSON-ready values; the match form is not stored."""
        return {
            "kind": self.kind,
            "value": self.value,
            "qualifier": self.qualifier,
            "encoding": self.encoding,
            "occurrences": [o.to_dict() for o in self.occurrences],
            "source": self.source,
            "meta": dict(self.meta),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Candidate:
        """Inverse of :meth:`to_dict`; a wrong shape or unknown key raises."""
        _check_keys("candidate", d, _CAND_KEYS)
        raw_occ = d.get("occurrences", [])
        if not isinstance(raw_occ, list | tuple):
            raise ValueError(f"occurrences must be a list, got {raw_occ!r}")
        meta = d.get("meta", {})
        if not isinstance(meta, dict):
            raise ValueError(f"meta must be an object, got {meta!r}")
        return cls(
            d["kind"],
            d["value"],
            qualifier=d.get("qualifier"),
            encoding=d.get("encoding"),
            occurrences=tuple(Occurrence.from_dict(o) for o in raw_occ),
            source=d.get("source"),
            meta=meta,
        )


# -- JSONL --------------------------------------------------------------------


def write_candidates_jsonl(path: Path, cands: Iterable[Candidate]) -> int:
    """Write one candidate per line; returns the count. Overwrites ``path``."""
    lines = [
        json.dumps(c.to_dict(), ensure_ascii=True, sort_keys=True, allow_nan=False)
        for c in cands
    ]
    with path.open("w", encoding="utf-8") as fh:  # opened only once all serialised
        for line in lines:
            fh.write(line)
            fh.write("\n")
    return len(lines)


def read_candidates_jsonl(
    path: Path,
) -> tuple[list[Candidate], dict[str, list[int]]]:
    """Read candidates back; bad lines are dropped by reason, with line numbers.

    ``bad_json``: the line isn't UTF-8 or doesn't parse (including integers too
    long to convert and nesting too deep to decode). ``bad_record``: it parses
    but isn't a valid candidate. Blank lines are skipped.
    """
    out: list[Candidate] = []
    dropped: dict[str, list[int]] = {}
    with path.open("rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                d = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                dropped.setdefault("bad_json", []).append(lineno)
                continue
            try:
                out.append(Candidate.from_dict(d))
            except (AttributeError, KeyError, TypeError, ValueError):
                dropped.setdefault("bad_record", []).append(lineno)
    return out, dropped

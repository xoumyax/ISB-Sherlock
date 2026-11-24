"""Frozen candidate IR shared by Exp 1 (report->rule) and Exp 2 (binary->rule).

The IR is *provenance-blind*: a candidate produced by a report IOC extractor and
one produced by byte-CNN attribution are the same kind of object, so every
downstream stage (grammar filter, pooling, selection, condition brain, scoring)
is written once.

Two value forms travel with every candidate and they are NOT interchangeable:

``value``
    Render form. Refanged (``hxxp``->``http``, ``[.]``->``.``) and, for hashes,
    whitespace-repaired -- but otherwise byte-faithful, because this is what
    gets written into a YARA string and has to match the real sample.
``norm``
    Match/dedup form. Case-folded for types where case is not meaningful
    (hashes, domains, filenames, paths, imports, sections), canonicalised
    uppercase-nospace for hex. Never rendered.

Rendering with ``norm`` would silently produce rules that cannot match; that is
why the two are separate fields rather than one "normalized value".
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

__all__ = [
    "CType",
    "TYPE_SPACE",
    "EXP1_TYPES",
    "EXP2_TYPES",
    "TYPE_ALIASES",
    "HASH_TYPES",
    "CASEFOLD_TYPES",
    "HEX_TYPES",
    "DEFANGABLE_TYPES",
    "canonical_ctype",
    "normalize_value",
    "render_value",
    "refang",
    "repair_split_hash",
    "Candidate",
    "dedupe",
    "has_non_ascii",
    "strip_unicode_punct",
]


# --------------------------------------------------------------------------
# Type space
# --------------------------------------------------------------------------

class CType:
    """Canonical candidate types (string constants, not an Enum).

    Plain strings keep JSONL round-tripping trivial and let call sites compare
    against extractor output without conversion.
    """

    # -- Exp 1: report-derived IOCs --------------------------------------
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    EMAIL = "EMAIL"
    FILE_NAME = "FILE_NAME"
    FILE_PATH = "FILE_PATH"
    REGISTRY_KEY = "REGISTRY_KEY"
    MUTEX = "MUTEX"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    HASH_IMPHASH = "HASH_IMPHASH"
    YARA_STR = "YARA_STR"
    YARA_HEX = "YARA_HEX"
    PE_ORIGINAL_FILENAME = "PE_ORIGINAL_FILENAME"
    PE_SECTION = "PE_SECTION"

    # -- Exp 2: binary-derived candidates --------------------------------
    STRING_ASCII = "STRING_ASCII"
    STRING_WIDE = "STRING_WIDE"
    IMPORT = "IMPORT"
    EXPORT = "EXPORT"
    PE_METADATA = "PE_METADATA"
    HEX_SPAN = "HEX_SPAN"


EXP1_TYPES = frozenset({
    CType.DOMAIN, CType.IP_ADDRESS, CType.URL, CType.EMAIL,
    CType.FILE_NAME, CType.FILE_PATH, CType.REGISTRY_KEY, CType.MUTEX,
    CType.HASH_MD5, CType.HASH_SHA1, CType.HASH_SHA256, CType.HASH_IMPHASH,
    CType.YARA_STR, CType.YARA_HEX,
    CType.PE_ORIGINAL_FILENAME, CType.PE_SECTION,
})

EXP2_TYPES = frozenset({
    CType.STRING_ASCII, CType.STRING_WIDE, CType.IMPORT, CType.EXPORT,
    CType.PE_SECTION, CType.PE_ORIGINAL_FILENAME, CType.PE_METADATA,
    CType.HEX_SPAN, CType.HASH_IMPHASH,
})

TYPE_SPACE = EXP1_TYPES | EXP2_TYPES

#: Upstream emitters use several spellings for the same concept. Canonicalising
#: at construction time is what makes pooling provenance-blind -- a section name
#: from ``pefile`` and one from the report NER must land on the same key.
TYPE_ALIASES: Mapping[str, str] = {
    "SECTION_NAME": CType.PE_SECTION,          # EXP2_DESIGN spelling
    "PE_SECTION_NAME": CType.PE_SECTION,
    "IMPHASH": CType.HASH_IMPHASH,             # ReportScooper spelling
    "PE_IMPHASH": CType.HASH_IMPHASH,
    "PE_IMPORT_DLL": CType.IMPORT,             # ReportScooper spelling
    "IMPORT_DLL": CType.IMPORT,
    "PE_EXPORT": CType.EXPORT,
    "MD5": CType.HASH_MD5,
    "SHA1": CType.HASH_SHA1,
    "SHA256": CType.HASH_SHA256,
    "IPV4": CType.IP_ADDRESS,
    "IP": CType.IP_ADDRESS,
    "HOSTNAME": CType.DOMAIN,
    "HEX": CType.YARA_HEX,
    "PE_VERSION_INFO": CType.PE_METADATA,
    "STRING": CType.STRING_ASCII,
}

HASH_TYPES = frozenset({
    CType.HASH_MD5, CType.HASH_SHA1, CType.HASH_SHA256, CType.HASH_IMPHASH,
})

#: Expected hex length per hash type; used by the whitespace-repair rejoin.
HASH_LENGTHS: Mapping[str, int] = {
    CType.HASH_MD5: 32,
    CType.HASH_IMPHASH: 32,
    CType.HASH_SHA1: 40,
    CType.HASH_SHA256: 64,
}

#: Any of these lengths is an acceptable rejoin target when the type is unknown.
_HASH_ANY_LENGTHS = (32, 40, 64)

#: Types whose case carries no information -> ``norm`` is lowercased, and the
#: grammar filter is allowed to render them ``nocase``.
CASEFOLD_TYPES = frozenset({
    CType.DOMAIN, CType.EMAIL, CType.URL,
    CType.FILE_NAME, CType.FILE_PATH, CType.REGISTRY_KEY,
    CType.PE_SECTION, CType.IMPORT, CType.PE_ORIGINAL_FILENAME,
}) | HASH_TYPES

HEX_TYPES = frozenset({CType.YARA_HEX, CType.HEX_SPAN})

DEFANGABLE_TYPES = frozenset({
    CType.DOMAIN, CType.IP_ADDRESS, CType.URL, CType.EMAIL,
})


def canonical_ctype(ctype: str) -> str:
    """Map an emitter's type spelling onto the canonical type space.

    Unknown types pass through upper-cased; the grammar filter rejects them with
    ``unknown_type`` rather than this function raising, so a new extractor label
    degrades to "not expressible" instead of crashing a whole run.
    """
    if not ctype:
        return ""
    t = ctype.strip().upper()
    return TYPE_ALIASES.get(t, t)


# --------------------------------------------------------------------------
# Value normalization
# --------------------------------------------------------------------------

_DEFANG_SUBS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bh(?:xx|XX|tt)p(s?)(?=\s*(?:\[|\(|:))", re.I), r"http\1"),
    (re.compile(r"\bh(?:xx|XX)p(s?)\b", re.I), r"http\1"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.I), "."),
    (re.compile(r"\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*at\s*\]", re.I), "@"),
    (re.compile(r"\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[\s*@\s*\]"), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*//\s*\]"), "//"),
)

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_WS = re.compile(r"\s+")


def refang(value: str) -> str:
    """Reverse the common defanging conventions used in threat reports."""
    out = value
    for pat, repl in _DEFANG_SUBS:
        out = pat.sub(repl, out)
    return out


def repair_split_hash(value: str, ctype: str | None = None) -> str:
    """Rejoin a hash split across PDF lines, but only on an exact length hit.

    Report PDFs wrap long hashes, so the extracted value arrives as
    ``"3a4b c5d6 ..."``. Stripping whitespace recovers it -- provided the result
    is hex of exactly the right length. Anything else is left untouched: an
    inexact rejoin would fabricate a hash that never appeared in the report.
    """
    if not value:
        return value
    stripped = _WS.sub("", value)
    if stripped == value:
        return value
    if not _HEX_ONLY.match(stripped):
        return value
    expected = HASH_LENGTHS.get(canonical_ctype(ctype or ""))
    targets = (expected,) if expected else _HASH_ANY_LENGTHS
    return stripped if len(stripped) in targets else value


_COMPACT_HEX = re.compile(r"^[0-9A-F?]+$")


def _canonical_hex(value: str) -> str:
    """Canonical hex-string body: uppercase, single-spaced byte tokens.

    Preserves YARA's hex constructions -- ``??`` wildcards, ``~`` not-operator,
    ``[n-m]`` jumps, ``(aa bb | cc)`` alternatives -- as distinct tokens, so
    grammar validation, fixed-byte counting, and equality all operate on the
    same tokenisation. Compact input (``E234??C8``) is split into byte pairs.
    """
    body = value.strip()
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1]
    body = _WS.sub(" ", body.upper()).strip()

    # Compact form with no separators: split into byte pairs.
    if " " not in body and _COMPACT_HEX.match(body) and len(body) % 2 == 0:
        body = " ".join(body[i:i + 2] for i in range(0, len(body), 2))

    # Jumps carry no internal spaces: "[ 4 - 6 ]" -> "[4-6]".
    body = re.sub(r"\[([^\]]*)\]", lambda m: "[" + _WS.sub("", m.group(1)) + "]", body)
    # Alternatives: no padding just inside the parens, single spaces around "|".
    body = re.sub(r"\(\s*", "(", body)
    body = re.sub(r"\s*\)", ")", body)
    body = re.sub(r"\s*\|\s*", " | ", body)
    # Separate grouping punctuation from adjacent byte tokens.
    body = re.sub(r"(?<=[0-9A-F?])(\[|\()", r" \1", body)
    body = re.sub(r"(\]|\))(?=[0-9A-F?~])", r"\1 ", body)
    return _WS.sub(" ", body).strip()


def render_value(value: str, ctype: str) -> str:
    """The byte-faithful form written into a rule (see module docstring)."""
    ctype = canonical_ctype(ctype)
    if value is None:
        return ""
    out = value.strip()
    if ctype in DEFANGABLE_TYPES or ctype == CType.URL:
        out = refang(out)
    if ctype in HASH_TYPES:
        out = repair_split_hash(out, ctype)
        out = _WS.sub("", out)
    if ctype in HEX_TYPES:
        out = _canonical_hex(out)
    return out


def normalize_value(value: str, ctype: str) -> str:
    """The match/dedup form (see module docstring). Never render this."""
    ctype = canonical_ctype(ctype)
    out = render_value(value, ctype)
    if ctype in HEX_TYPES:
        return out  # already uppercase-canonical
    if ctype in CASEFOLD_TYPES:
        out = out.lower()
    if ctype in (CType.FILE_PATH, CType.REGISTRY_KEY):
        # Windows separators are interchangeable for matching purposes.
        out = out.replace("/", "\\")
        out = re.sub(r"\\{2,}", r"\\", out)
    return out


# --------------------------------------------------------------------------
# Candidate
# --------------------------------------------------------------------------

@dataclass(frozen=True, eq=False)
class Candidate:
    """One renderable observation about a sample or a report.

    Equality and hashing are on :meth:`key` -- (ctype, norm, encoding) -- so
    ``attrs`` can carry per-run scores without splitting what is conceptually
    the same candidate into duplicates during pooling.
    """

    value: str
    ctype: str
    encoding: str | None = None
    source: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    #: Match/dedup form, derived in ``__post_init__``. Never rendered.
    norm: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        ctype = canonical_ctype(self.ctype)
        object.__setattr__(self, "ctype", ctype)
        object.__setattr__(self, "value", render_value(self.value, ctype))
        if self.encoding is None:
            enc = "hex" if ctype in HEX_TYPES else (
                "wide" if ctype == CType.STRING_WIDE else "ascii"
            )
            object.__setattr__(self, "encoding", enc)
        object.__setattr__(self, "norm", normalize_value(self.value, ctype))

    # -- identity ------------------------------------------------------
    def key(self) -> tuple[str, str, str]:
        return (self.ctype, self.norm, self.encoding or "")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Candidate) and self.key() == other.key()

    def __hash__(self) -> int:
        return hash(self.key())

    # -- serialization -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "ctype": self.ctype,
            "encoding": self.encoding,
            "source": self.source,
            "attrs": dict(self.attrs),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Candidate":
        return cls(
            value=d["value"],
            ctype=d["ctype"],
            encoding=d.get("encoding"),
            source=d.get("source"),
            attrs=dict(d.get("attrs") or {}),
        )

    @classmethod
    def from_ioc(
        cls,
        value: str,
        ioc_type: str,
        source: str | None = None,
        strict: bool = False,
        **attrs: Any,
    ) -> "Candidate":
        """Build from an extractor's ``(value, type)`` pair.

        ``strict=True`` raises on a type outside :data:`TYPE_SPACE`; the default
        is permissive so an unexpected extractor label is dropped later by the
        grammar filter (with a reason) instead of aborting a whole run.
        """
        ctype = canonical_ctype(ioc_type)
        if strict and ctype not in TYPE_SPACE:
            raise ValueError(f"type outside TYPE_SPACE: {ioc_type!r} -> {ctype!r}")
        return cls(value=value, ctype=ctype, source=source, attrs=dict(attrs))

    # -- convenience ---------------------------------------------------
    @property
    def is_hash(self) -> bool:
        return self.ctype in HASH_TYPES

    @property
    def is_hex(self) -> bool:
        return self.ctype in HEX_TYPES

    @property
    def printable_len(self) -> int:
        """Length in "meaningful" characters; hex counts fixed bytes."""
        if self.is_hex:
            return sum(
                1 for t in self.norm.split(" ")
                if len(t) == 2 and "?" not in t and not t.startswith("~")
            )
        return len(self.value)


def dedupe(cands: Iterable[Candidate]) -> list[Candidate]:
    """Stable de-duplication on :meth:`Candidate.key`, first occurrence wins."""
    seen: set[tuple[str, str, str]] = set()
    out: list[Candidate] = []
    for c in cands:
        k = c.key()
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def has_non_ascii(value: str) -> bool:
    return any(ord(ch) > 0x7F for ch in value)


def strip_unicode_punct(value: str) -> str:
    """Fold typographic punctuation PDFs introduce into ASCII equivalents."""
    table = {
        "‘": "'", "’": "'", "“": '"', "”": '"',
        "–": "-", "—": "-", "…": "...", " ": " ",
    }
    out = "".join(table.get(ch, ch) for ch in value)
    return unicodedata.normalize("NFKC", out)

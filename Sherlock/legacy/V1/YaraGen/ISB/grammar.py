"""YARA grammar filter: what can be expressed, and how to render it.

Anchored to ``Agent/YaraGuide/yara_documentation.md`` (the official docs):

* keyword list and identifier rules -- doc lines 341-366
* text-string escape sequences and the ASCII-only rule -- doc lines 564-604
* hex-string constructions (wildcards, ``~`` not, ``[n-m]`` jumps,
  ``(a|b)`` alternatives) -- doc lines 419-563
* string-modifier legality matrix -- doc lines 985-1002

Deliberately pure-python: no ``yaramod`` import at module scope, because
``yaramod`` must be imported before anything that pulls HuggingFace
``evaluate``/TensorFlow, and this module gets imported from everywhere. Real
parse validation belongs to the generation gate, not here.

Two render kinds exist, and the distinction drives the whole condition shape:

``string``
    Goes in the ``strings:`` section as ``$id = ...``.
``module``
    Cannot be a string at all -- a file hash is a property of the file, not a
    byte sequence inside it -- so it renders as a condition term such as
    ``hash.sha256(0, filesize) == "..."`` and forces an ``import``.
"""

from __future__ import annotations

import re
import string as _string
from dataclasses import dataclass
from typing import Iterable, Sequence

from .candidate import (
    CASEFOLD_TYPES,
    HASH_TYPES,
    HEX_TYPES,
    TYPE_SPACE,
    Candidate,
    CType,
    has_non_ascii,
)

__all__ = [
    "YARA_KEYWORDS",
    "RenderKind",
    "Expressibility",
    "GrammarConfig",
    "render_kind",
    "expressible",
    "filter_expressible",
    "escape_text",
    "safe_identifier",
    "sanitize_rule_name",
    "validate_modifiers",
    "validate_hex_body",
    "required_modules",
    "render_string",
    "render_module_term",
]


# -- doc lines 348-358 -----------------------------------------------------
YARA_KEYWORDS = frozenset({
    "all", "and", "any", "ascii", "at", "base64", "base64wide", "condition",
    "contains", "endswith", "entrypoint", "false", "filesize", "for",
    "fullword", "global", "import", "icontains", "iendswith", "iequals", "in",
    "include", "int16", "int16be", "int32", "int32be", "int8", "int8be",
    "istartswith", "matches", "meta", "nocase", "none", "not", "of", "or",
    "private", "rule", "startswith", "strings", "them", "true", "uint16",
    "uint16be", "uint32", "uint32be", "uint8", "uint8be", "wide", "xor",
    "defined",
})


class RenderKind:
    STRING = "string"
    MODULE = "module"
    NONE = "none"


#: Which types become condition terms via a module rather than ``strings:``.
_MODULE_TYPES = frozenset(HASH_TYPES)

#: Module needed per module-rendered type.
_MODULE_OF: dict[str, str] = {
    CType.HASH_MD5: "hash",
    CType.HASH_SHA1: "hash",
    CType.HASH_SHA256: "hash",
    CType.HASH_IMPHASH: "pe",
}

_HASH_FN: dict[str, str] = {
    CType.HASH_MD5: "hash.md5(0, filesize)",
    CType.HASH_SHA1: "hash.sha1(0, filesize)",
    CType.HASH_SHA256: "hash.sha256(0, filesize)",
}


@dataclass(frozen=True)
class GrammarConfig:
    """Tunable expressibility thresholds. Defaults are the F_dev/tune knobs."""

    #: Minimum characters for a text string. Short atoms are FP engines; 4 keeps
    #: real section names (".text", "UPX0") while dropping 1-3 char noise.
    min_string_len: int = 4
    #: Minimum *fixed* (non-wildcard) bytes in a hex string.
    min_hex_fixed_bytes: int = 4
    #: Maximum rendered string length; longer values are usually parse garbage.
    max_string_len: int = 512
    #: Minimum count of "atom-worthy" characters (alnum or punctuation that is
    #: not whitespace). A value of only whitespace/padding cannot anchor a scan.
    min_atom_chars: int = 4
    #: Allow non-ASCII by rejecting (False) vs hex-escaping (True).
    hex_escape_non_ascii: bool = True


DEFAULT_CONFIG = GrammarConfig()


@dataclass(frozen=True)
class Expressibility:
    """Verdict object. Truthy iff expressible, and carries the reject reason."""

    ok: bool
    reason: str | None = None
    kind: str = RenderKind.NONE

    def __bool__(self) -> bool:
        return self.ok


_OK_STRING = Expressibility(True, None, RenderKind.STRING)
_OK_MODULE = Expressibility(True, None, RenderKind.MODULE)


def render_kind(ctype: str) -> str:
    if ctype in _MODULE_TYPES:
        return RenderKind.MODULE
    if ctype in TYPE_SPACE:
        return RenderKind.STRING
    return RenderKind.NONE


# --------------------------------------------------------------------------
# Identifiers
# --------------------------------------------------------------------------

_IDENT_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def safe_identifier(base: str, index: int | None = None, prefix: str = "$") -> str:
    """Build a legal string identifier (``$`` + alnum/underscore, doc line 364).

    ``index`` disambiguates; a bare sanitized base that collides with a YARA
    keyword gets suffixed rather than silently producing an unparseable rule.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", base or "s").strip("_") or "s"
    if cleaned[0].isdigit():
        cleaned = "s" + cleaned
    if cleaned.lower() in YARA_KEYWORDS:
        cleaned = cleaned + "_"
    if index is not None:
        cleaned = f"{cleaned}{index}"
    return prefix + cleaned[:60]


def sanitize_rule_name(name: str) -> str:
    """Legal rule name: identifier rules plus the keyword exclusion."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name or "rule").strip("_") or "rule"
    if cleaned[0].isdigit():
        cleaned = "r_" + cleaned
    if cleaned.lower() in YARA_KEYWORDS:
        cleaned = cleaned + "_rule"
    if not _IDENT_OK.match(cleaned):
        cleaned = "rule_" + re.sub(r"\W", "_", cleaned)
    return cleaned[:128]


# --------------------------------------------------------------------------
# Text strings
# --------------------------------------------------------------------------

#: doc lines 587-594 -- the only escapes YARA text strings accept.
_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\r": "\\r",
    "\n": "\\n",
    "\t": "\\t",
}

_PRINTABLE = set(_string.printable) - set("\r\n\t\x0b\x0c")


def escape_text(value: str, hex_escape_non_ascii: bool = True) -> str:
    """Escape a value for a YARA text string.

    Backslash is handled first (via the table, one pass) so an escaped
    backslash is not re-escaped. Anything outside YARA's escape subset becomes
    ``\\xdd``, which is the doc-sanctioned way to place arbitrary bytes in a
    text string.
    """
    out: list[str] = []
    for ch in value:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch in _PRINTABLE:
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        elif hex_escape_non_ascii:
            out.extend(f"\\x{b:02x}" for b in ch.encode("utf-8"))
        else:
            out.append("?")
    return "".join(out)


# doc lines 991-1002 -- modifier legality matrix.
_MOD_CONFLICTS: dict[str, frozenset[str]] = {
    "nocase": frozenset({"xor", "base64", "base64wide"}),
    "xor": frozenset({"nocase", "base64", "base64wide"}),
    "base64": frozenset({"nocase", "xor", "fullword"}),
    "base64wide": frozenset({"nocase", "xor", "fullword"}),
    "fullword": frozenset({"base64", "base64wide"}),
}

_TEXT_ONLY_MODS = frozenset({"xor", "base64", "base64wide"})
_TEXT_OR_REGEX_MODS = frozenset({"nocase", "wide", "ascii", "fullword"})
_HEX_MODS = frozenset({"private"})
_ALL_MODS = _TEXT_ONLY_MODS | _TEXT_OR_REGEX_MODS | frozenset({"private"})


def validate_modifiers(mods: Sequence[str], string_type: str = "text") -> Expressibility:
    """Check a modifier list against the doc's legality matrix.

    ``string_type`` is ``text``, ``regex`` or ``hex``; hex strings accept only
    ``private``.
    """
    seen = [m.strip().lower() for m in mods if m and m.strip()]
    for m in seen:
        if m not in _ALL_MODS:
            return Expressibility(False, f"unknown_modifier:{m}")
        if string_type == "hex" and m not in _HEX_MODS:
            return Expressibility(False, f"modifier_not_on_hex:{m}")
        if string_type == "regex" and m in _TEXT_ONLY_MODS:
            return Expressibility(False, f"modifier_not_on_regex:{m}")
    for m in seen:
        clash = _MOD_CONFLICTS.get(m, frozenset()).intersection(seen)
        if clash:
            return Expressibility(False, f"modifier_conflict:{m}+{sorted(clash)[0]}")
    return Expressibility(True, None)


def default_modifiers(cand: Candidate) -> list[str]:
    """Modifiers we attach by default, per type.

    ``nocase`` only where case genuinely carries no information (the same set
    that drives ``norm`` case-folding), and never on hex. ``wide ascii`` for
    wide-encoded strings so both encodings match.
    """
    if cand.is_hex:
        return []
    mods: list[str] = []
    if cand.encoding == "wide":
        mods += ["wide", "ascii"]
    if cand.ctype in CASEFOLD_TYPES and cand.ctype not in HASH_TYPES:
        mods.append("nocase")
    if cand.ctype in (CType.IMPORT, CType.EXPORT, CType.PE_SECTION):
        mods.append("fullword")
    return mods


# --------------------------------------------------------------------------
# Hex strings
# --------------------------------------------------------------------------

_HEX_BYTE = re.compile(r"^(?:[0-9A-F]{2}|[0-9A-F]\?|\?[0-9A-F]|\?\?)$")
_HEX_NOT = re.compile(r"^~(?:[0-9A-F]{2}|[0-9A-F]\?|\?[0-9A-F]|\?\?)$")
_HEX_JUMP = re.compile(r"^\[(?:\d+|\d*-\d*)\]$")


def _hex_tokens(body: str) -> list[str]:
    return [t for t in body.strip().split(" ") if t]


def validate_hex_body(
    body: str, config: GrammarConfig = DEFAULT_CONFIG
) -> Expressibility:
    """Validate a canonicalised hex-string body (no surrounding braces).

    Enforces the doc's constructions, rejects jumps at either edge, and requires
    enough fixed bytes to be a usable atom.

    Deliberately a little stricter than yara 4.5.4 -- e.g. it rejects nested
    alternations that yara actually accepts. Strict is the safe direction here: a
    candidate dropped with a reason is auditable, whereas one that reaches the
    generator and fails to compile costs a whole cell of the grid.
    """
    tokens = _hex_tokens(body)
    if not tokens:
        return Expressibility(False, "hex_empty")

    fixed = 0
    depth = 0
    for i, tok in enumerate(tokens):
        if tok == "|":
            if depth == 0:
                return Expressibility(False, "hex_alt_outside_group")
            continue
        # Alternatives group: tokens were canonicalised so "(" glues to the
        # first byte of the branch, ")" to the last.
        opens = tok.startswith("(")
        closes = tok.endswith(")")
        core = tok[1:] if opens else tok
        core = core[:-1] if closes and core.endswith(")") else core
        if opens:
            depth += 1
        if closes:
            depth -= 1
            if depth < 0:
                return Expressibility(False, "hex_unbalanced_group")

        if _HEX_JUMP.match(core):
            if i == 0 or i == len(tokens) - 1:
                return Expressibility(False, "hex_jump_at_edge")
            lo_hi = core[1:-1]
            if "-" in lo_hi:
                lo, hi = lo_hi.split("-", 1)
                if lo and hi and int(lo) > int(hi):
                    return Expressibility(False, "hex_jump_reversed")
            continue
        if _HEX_NOT.match(core):
            continue
        if core and _HEX_BYTE.match(core):
            if "?" not in core:
                fixed += 1
            continue
        if core == "":
            continue
        return Expressibility(False, f"hex_bad_token:{tok[:8]}")

    if depth != 0:
        return Expressibility(False, "hex_unbalanced_group")
    if fixed < config.min_hex_fixed_bytes:
        return Expressibility(False, f"hex_too_few_fixed_bytes:{fixed}")
    return Expressibility(True, None, RenderKind.STRING)


# --------------------------------------------------------------------------
# Expressibility
# --------------------------------------------------------------------------

_HEX_HASH = re.compile(r"^[0-9a-f]+$")


def _atom_chars(value: str) -> int:
    return sum(1 for ch in value if not ch.isspace())


def expressible(
    cand: Candidate, config: GrammarConfig = DEFAULT_CONFIG
) -> Expressibility:
    """Can this candidate be rendered into a static YARA rule?

    Runs *after* selection in Exp 2 (EXP2_DESIGN §7) so selection metrics are
    not distorted by renderability, and as the shared expressibility filter in
    Exp 1 (EXP1_DESIGN §5) -- identical rules for every arm, which is what makes
    the arms comparable.
    """
    kind = render_kind(cand.ctype)
    if kind == RenderKind.NONE:
        return Expressibility(False, "unknown_type")

    value = cand.value
    if not value or not value.strip():
        return Expressibility(False, "empty_value")

    if kind == RenderKind.MODULE:
        expected = {CType.HASH_MD5: 32, CType.HASH_IMPHASH: 32,
                    CType.HASH_SHA1: 40, CType.HASH_SHA256: 64}[cand.ctype]
        if not _HEX_HASH.match(cand.norm):
            return Expressibility(False, "hash_not_hex")
        if len(cand.norm) != expected:
            return Expressibility(False, f"hash_wrong_length:{len(cand.norm)}")
        return _OK_MODULE

    if cand.is_hex:
        return validate_hex_body(cand.norm, config)

    if len(value) < config.min_string_len:
        return Expressibility(False, f"too_short:{len(value)}")
    if len(value) > config.max_string_len:
        return Expressibility(False, f"too_long:{len(value)}")
    if _atom_chars(value) < config.min_atom_chars:
        return Expressibility(False, "no_atom")
    if has_non_ascii(value) and not config.hex_escape_non_ascii:
        return Expressibility(False, "non_ascii")

    mods = validate_modifiers(default_modifiers(cand), "text")
    if not mods:
        return Expressibility(False, mods.reason)
    return _OK_STRING


def filter_expressible(
    cands: Iterable[Candidate], config: GrammarConfig = DEFAULT_CONFIG
) -> tuple[list[Candidate], dict[str, list[Candidate]]]:
    """Split candidates into kept and rejected-by-reason.

    Returning the rejection buckets (rather than just the survivors) is what
    lets Exp 1 report *why* extraction output was dropped instead of showing an
    unexplained coverage gap.
    """
    kept: list[Candidate] = []
    dropped: dict[str, list[Candidate]] = {}
    for c in cands:
        verdict = expressible(c, config)
        if verdict:
            kept.append(c)
        else:
            dropped.setdefault(verdict.reason or "unknown", []).append(c)
    return kept, dropped


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def required_modules(cands: Iterable[Candidate]) -> list[str]:
    """Sorted module imports needed by the module-rendered candidates."""
    mods = {
        _MODULE_OF[c.ctype]
        for c in cands
        if render_kind(c.ctype) == RenderKind.MODULE and c.ctype in _MODULE_OF
    }
    return sorted(mods)


def render_string(
    cand: Candidate,
    identifier: str,
    config: GrammarConfig = DEFAULT_CONFIG,
    modifiers: Sequence[str] | None = None,
) -> str:
    """Render one ``strings:`` line. Raises if the candidate is not expressible.

    Callers filter first; raising here turns a silently malformed rule into a
    loud bug.
    """
    verdict = expressible(cand, config)
    if not verdict:
        raise ValueError(f"not expressible ({verdict.reason}): {cand!r}")
    if verdict.kind != RenderKind.STRING:
        raise ValueError(f"{cand.ctype} renders as a module term, not a string")

    if cand.is_hex:
        return f"{identifier} = {{ {cand.norm} }}"

    mods = list(modifiers) if modifiers is not None else default_modifiers(cand)
    mod_check = validate_modifiers(mods, "text")
    if not mod_check:
        raise ValueError(f"illegal modifiers {mods}: {mod_check.reason}")
    suffix = (" " + " ".join(mods)) if mods else ""
    return f'{identifier} = "{escape_text(cand.value, config.hex_escape_non_ascii)}"{suffix}'


def render_module_term(cand: Candidate, config: GrammarConfig = DEFAULT_CONFIG) -> str:
    """Render one module-based condition term (hashes, imphash)."""
    verdict = expressible(cand, config)
    if not verdict:
        raise ValueError(f"not expressible ({verdict.reason}): {cand!r}")
    if verdict.kind != RenderKind.MODULE:
        raise ValueError(f"{cand.ctype} renders as a string, not a module term")
    if cand.ctype == CType.HASH_IMPHASH:
        return f'pe.imphash() == "{cand.norm}"'
    return f'{_HASH_FN[cand.ctype]} == "{cand.norm}"'

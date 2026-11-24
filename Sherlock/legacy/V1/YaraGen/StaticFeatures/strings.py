"""Byte-scan string extraction (ASCII and UTF-16LE).

Values only -- no offsets. Offsets would multiply the cache size for information
nothing downstream uses: candidates are matched by value, and YARA locates them
itself at scan time.

Results are de-duplicated per file and sorted, which keeps the cache
deterministic (byte-identical shards on a re-run) and makes the set-membership
pooling in ``YaraGen/ISB/pooling.py`` a straight ``in`` test.
"""

from __future__ import annotations

import re

__all__ = [
    "MIN_STRING_LEN",
    "extract_ascii_strings",
    "extract_wide_strings",
    "extract_strings",
]

#: Minimum length for an extracted string. 6 is the extraction floor (a cache
#: sizing decision); expressibility has its own, lower floor in ISB/grammar.py.
MIN_STRING_LEN = 6

#: Printable ASCII run.
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)

#: UTF-16LE run: printable ASCII byte followed by a NUL, repeated.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN)


def extract_ascii_strings(data: bytes, min_len: int = MIN_STRING_LEN,
                          cap: int | None = None) -> tuple[list[str], bool]:
    """Extract printable ASCII strings. Returns ``(sorted_unique, truncated)``."""
    out: set[str] = set()
    truncated = False
    pattern = _ASCII_RE if min_len == MIN_STRING_LEN else re.compile(
        rb"[\x20-\x7e]{%d,}" % min_len)
    for m in pattern.finditer(data):
        out.add(m.group().decode("ascii", "ignore"))
        if cap is not None and len(out) >= cap:
            truncated = True
            break
    return sorted(out), truncated


def extract_wide_strings(data: bytes, min_len: int = MIN_STRING_LEN,
                         cap: int | None = None) -> tuple[list[str], bool]:
    """Extract UTF-16LE strings. Returns ``(sorted_unique, truncated)``."""
    out: set[str] = set()
    truncated = False
    pattern = _WIDE_RE if min_len == MIN_STRING_LEN else re.compile(
        rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in pattern.finditer(data):
        out.add(m.group().decode("utf-16-le", "ignore"))
        if cap is not None and len(out) >= cap:
            truncated = True
            break
    return sorted(out), truncated


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN,
                    cap: int | None = None) -> dict:
    """Both encodings in one pass-pair.

    ``cap`` applies per encoding rather than as a shared budget: a shared budget
    spent on ASCII would silently leave a string-heavy sample with zero wide
    strings, which looks like "this family uses no wide strings" instead of
    "we stopped looking".
    """
    ascii_vals, ascii_trunc = extract_ascii_strings(data, min_len, cap)
    wide_vals, wide_trunc = extract_wide_strings(data, min_len, cap)
    return {
        "strings_ascii": ascii_vals,
        "strings_wide": wide_vals,
        "strings_truncated": bool(ascii_trunc or wide_trunc),
    }

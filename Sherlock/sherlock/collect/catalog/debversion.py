"""dpkg version comparison (deb-version(7)), for keeping the newest package.

PMC keeps many historical versions of each package in one Packages file and Ubuntu
splits a release across ``noble`` and ``noble-updates``, so the apt planner needs the
real dpkg order to pick the newest: epoch first, then upstream, then revision, each
compared by dpkg's alternating non-digit / digit runs where ``~`` sorts before
everything (even the end of the string) and letters sort before other non-digits.
A plain string or ``packaging.version`` compare gets ``1.0~rc1 < 1.0`` and
``8.0.11-0ubuntu1~24.04.1 < 8.0.11-0ubuntu1`` wrong.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any

__all__ = ["compare", "parse", "sort_key"]

_UPSTREAM = re.compile(r"^[0-9][A-Za-z0-9.+~:-]*$")
_REVISION = re.compile(r"^[A-Za-z0-9.+~]+$")


def parse(version: str) -> tuple[int, str, str]:
    """Split ``[epoch:]upstream[-revision]``; raise ValueError if malformed."""
    if not isinstance(version, str) or not version or version != version.strip():
        raise ValueError(f"bad dpkg version {version!r}")
    epoch = 0
    rest = version
    if ":" in version:
        e, rest = version.split(":", 1)
        if not e.isdigit():
            raise ValueError(f"bad epoch in dpkg version {version!r}")
        epoch = int(e)
    upstream, revision = rest, ""
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
        if not _REVISION.match(revision):
            raise ValueError(f"bad revision in dpkg version {version!r}")
    if not _UPSTREAM.match(upstream):
        raise ValueError(f"bad upstream in dpkg version {version!r}")
    return epoch, upstream, revision


def _order(s: str, i: int) -> int:
    if i >= len(s):
        return 0
    c = s[i]
    if c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (
            j < len(b) and not b[j].isdigit()
        ):
            ac, bc = _order(a, i), _order(b, j)
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare(a: str, b: str) -> int:
    """Negative if ``a < b``, zero if equal, positive if ``a > b`` (dpkg order)."""
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _verrevcmp(ua, ub)
    if c:
        return -1 if c < 0 else 1
    c = _verrevcmp(ra, rb)
    return 0 if c == 0 else (-1 if c < 0 else 1)


#: ``sorted(versions, key=sort_key)`` sorts ascending in dpkg order.
sort_key: Callable[[str], Any] = functools.cmp_to_key(compare)

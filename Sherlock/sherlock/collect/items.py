"""The contract between catalogue planners and the fetcher.

A planner reads a source's catalogue (through an injected ``Getter``, so tests run
offline) and returns a ``CatalogResult``: the payloads to fetch, each anchored by a
catalogue checksum, plus the exact catalogue bytes ("anchors") that the plan keeps
so the chain can be re-checked later (for example gpgv on an apt InRelease).

Only SHA-256 and SHA-512 count as anchors; MD5 and SHA-1 never do.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = ["DIGEST_HEX_LEN", "CatalogResult", "Getter", "PlanItem"]

#: Accepted anchor algorithms and their hex lengths.
DIGEST_HEX_LEN = {"sha256": 64, "sha512": 128}

#: ``get(url, max_bytes) -> body``. Raises on HTTP/TLS errors or an oversize body.
Getter = Callable[[str, int], bytes]

_HEX = re.compile(r"^[0-9a-f]+$")


@dataclass(frozen=True)
class PlanItem:
    """One payload to fetch.

    ``meta`` is JSON-able and holds the provenance a row needs later: ``package``,
    ``version``, ``catalog_url`` (the catalogue entry, never a sample URL),
    ``source_date`` (ISO date or None) with ``date_kind``, ``vendor_evidence`` and
    ``licence``. Never an inventory time (H6).
    """

    source: str
    key: str
    url: str
    expected: Mapping[str, str]
    size: int | None = None
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source or not self.key:
            raise ValueError("source and key are required")
        if not self.url.startswith("https://"):
            raise ValueError(f"{self.key}: payload URL must be https")
        if not self.expected:
            raise ValueError(f"{self.key}: no SHA-256/SHA-512 anchor")
        for alg, hexd in self.expected.items():
            if alg not in DIGEST_HEX_LEN:
                raise ValueError(f"{self.key}: {alg!r} is not an accepted anchor")
            if len(hexd) != DIGEST_HEX_LEN[alg] or not _HEX.match(hexd):
                raise ValueError(f"{self.key}: bad {alg} digest")
        if self.size is not None and self.size < 0:
            raise ValueError(f"{self.key}: negative size")
        object.__setattr__(self, "expected", dict(sorted(self.expected.items())))
        object.__setattr__(self, "meta", dict(self.meta))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "key": self.key,
            "url": self.url,
            "expected": dict(self.expected),
            "size": self.size,
            "meta": dict(self.meta),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> PlanItem:
        return cls(
            source=d["source"],
            key=d["key"],
            url=d["url"],
            expected=d["expected"],
            size=d.get("size"),
            meta=d.get("meta") or {},
        )


@dataclass(frozen=True)
class CatalogResult:
    """What a planner returns.

    ``anchors``: name -> exact catalogue bytes kept with the plan (InRelease,
    Packages, the winget commit id, NuGet search pages). ``dropped``: reason -> count.
    ``stats``: JSON-able counts for the run record.
    """

    source: str
    items: tuple[PlanItem, ...]
    anchors: Mapping[str, bytes] = field(default_factory=dict)
    dropped: Mapping[str, int] = field(default_factory=dict)
    stats: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        keys = [i.key for i in self.items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate plan item keys")

    def summary(self) -> dict[str, Any]:
        known = [i.size for i in self.items if i.size is not None]
        return {
            "source": self.source,
            "n_items": len(self.items),
            "n_unknown_size": len(self.items) - len(known),
            "declared_bytes": sum(known),
            "dropped": dict(self.dropped),
            **dict(self.stats),
        }

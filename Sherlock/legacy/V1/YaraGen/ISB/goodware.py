"""Goodware genericity lookup, routed by candidate type.

Two indexes answer two different questions, and a candidate must be asked the
right one:

* **string DF index** (``StaticFeatures/dfindex.py``) -- exact lookup over whole
  extracted values. Correct for strings, imports, section names, PE metadata.
* **span presence index** (``StaticFeatures/spanindex.py``) -- substring search
  over goodware bytes. The only thing that can score a ``HEX_SPAN``, which is an
  arbitrary byte range and need not align with any extracted string.

Asking the string index about a hex span returns 0 for *every* span, which reads
as "absent from all goodware" -- the most dangerous possible wrong answer, since
absence from goodware is exactly what promotes a candidate. :class:`GoodwareOracle`
exists so that mistake cannot be made by omission: it routes on ``ctype``.

The two indexes also legitimately disagree on ``n_docs`` (the string index caps
per source at 2000 to stop UCSB defining "generic"; the span index scans the
whole side because presence is zero-tolerance). Rates are therefore always taken
against the *originating* index's document count, never a shared one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .candidate import HEX_TYPES, Candidate
from .pooling import DFIndex

__all__ = ["GoodwareVerdict", "GoodwareOracle"]


@dataclass(frozen=True)
class GoodwareVerdict:
    """How generic a candidate is, and which index said so."""

    count: int
    n_docs: int
    index: str          # "strings" | "spans" | "none"

    @property
    def rate(self) -> float:
        return self.count / self.n_docs if self.n_docs else 0.0

    @property
    def absent(self) -> bool:
        """True iff no goodware document carries this value.

        ``n_docs == 0`` means nothing was scanned, and an unasked question is
        not evidence of absence -- so an empty index never reports ``absent``.
        """
        return self.n_docs > 0 and self.count == 0

    def __bool__(self) -> bool:      # truthy == "seen in goodware"
        return self.count > 0


class GoodwareOracle:
    """Routes a candidate to whichever index can actually score it."""

    def __init__(
        self,
        strings: DFIndex | None = None,
        spans: DFIndex | None = None,
        span_types: Iterable[str] = HEX_TYPES,
    ):
        self.strings = strings or DFIndex()
        self.spans = spans or DFIndex()
        self.span_types = frozenset(span_types)

    def index_for(self, ctype: str) -> tuple[DFIndex, str]:
        if ctype in self.span_types:
            return self.spans, "spans"
        return self.strings, "strings"

    def verdict(self, cand: Candidate) -> GoodwareVerdict:
        index, name = self.index_for(cand.ctype)
        if not index.n_docs:
            # Unscored, and said so. Callers that need a real answer check
            # ``scored_types`` first rather than reading 0 as "clean".
            return GoodwareVerdict(count=0, n_docs=0, index="none")
        return GoodwareVerdict(
            count=index.count(cand.norm), n_docs=index.n_docs, index=name)

    def count(self, cand: Candidate) -> int:
        return self.verdict(cand).count

    def is_absent(self, cand: Candidate) -> bool:
        """Absent from goodware *and* actually looked for."""
        return self.verdict(cand).absent

    @property
    def scored_types(self) -> dict[str, bool]:
        """Which halves of the type space have a usable index behind them.

        Supervision reports this so a run that silently had no span index --
        and therefore could not have labelled a single ``HEX_SPAN`` honestly --
        is visible in the artifact rather than inferred from a suspicious yield.
        """
        return {"strings": self.strings.n_docs > 0, "spans": self.spans.n_docs > 0}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"GoodwareOracle(strings={self.strings.n_docs} docs, "
                f"spans={self.spans.n_docs} docs)")

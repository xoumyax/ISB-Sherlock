"""Per-source transfer budget ledger, persisted as JSON (COLLECT §2 Ledger).

The V1-era kit's reservations ate its 8 GiB cap because they were never released.
Here every request reserves before it starts and settles when it ends:

* the reservation is the declared size, or ``unknown_size_reserve_bytes`` when the
  catalogue gives none;
* success charges the bytes read and releases the rest;
* a failure after any payload byte keeps (charges) the full reservation when the
  size was declared; for an unknown size it charges ``min(reservation,
  bytes_read)``, so a dropped stream does not cost 512 MiB (review M1, 25 Nov);
* a failure before any payload byte is refunded (a declared Content-Length over
  the reservation is refused before reading, so it is refunded too);
* a stream that passes its reservation is aborted by the caller (download
  ``max_bytes`` = reservation) and charged in full;
* cache replay never touches the ledger, so it costs nothing.

One file per source (``intake/<source>/ledger.json``), so the budget is the
source's, across plans. Reservations still open when the file is loaded belong to
a process that died mid-request; nobody knows how much it read, so they are charged
in full. Every change is written atomically (temp file + rename).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["DEFAULT_CONFIG", "BudgetExhausted", "Ledger", "LedgerConfig"]


@dataclass(frozen=True)
class LedgerConfig:
    #: Reservation for a payload of unknown size (the kit's per-file cap).
    unknown_size_reserve_bytes: int = 512 << 20


DEFAULT_CONFIG = LedgerConfig()


class BudgetExhausted(Exception):
    """The next reservation does not fit in what is left of the budget."""


class Ledger:
    def __init__(
        self,
        path: Path,
        budget_bytes: int,
        config: LedgerConfig = DEFAULT_CONFIG,
    ) -> None:
        if budget_bytes < 0:
            raise ValueError("budget_bytes must be >= 0")
        self.path = path
        self.config = config
        self.budget_bytes = int(budget_bytes)
        self.spent = 0
        self.open: dict[str, int] = {}
        #: Keys of open reservations whose size was not declared.
        self.unknown: set[str] = set()
        self.counts = {
            "n_charged_ok": 0,
            "n_charged_failed": 0,
            "n_refunded": 0,
            "n_orphans_charged": 0,
        }
        self._load()

    # -- persistence ----------------------------------------------------------
    def _load(self) -> None:
        if not self.path.is_file():
            return
        d = json.loads(self.path.read_text(encoding="utf-8"))
        self.spent = int(d.get("spent", 0))
        for k in self.counts:
            self.counts[k] = int(d.get("counts", {}).get(k, 0))
        orphans = {str(k): int(v) for k, v in (d.get("open") or {}).items()}
        if orphans:
            self.spent += sum(orphans.values())
            self.counts["n_orphans_charged"] += len(orphans)
            self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        body = {
            "budget_bytes": self.budget_bytes,
            "spent": self.spent,
            "open": self.open,
            "unknown": sorted(self.unknown),
            "counts": self.counts,
        }
        tmp.write_text(json.dumps(body, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    # -- accounting -----------------------------------------------------------
    @property
    def reserved(self) -> int:
        return sum(self.open.values())

    @property
    def remaining(self) -> int:
        return max(0, self.budget_bytes - self.spent - self.reserved)

    def set_budget(self, budget_bytes: int) -> None:
        if budget_bytes < 0:
            raise ValueError("budget_bytes must be >= 0")
        self.budget_bytes = int(budget_bytes)
        self._save()

    def reserve(self, key: str, declared_size: int | None) -> int:
        """Reserve for ``key``; returns the amount (use it as download max_bytes)."""
        if key in self.open:
            raise ValueError(f"{key!r} already holds a reservation; settle it first")
        amount = (
            self.config.unknown_size_reserve_bytes
            if declared_size is None
            else int(declared_size)
        )
        if amount > self.remaining:
            raise BudgetExhausted(
                f"reservation of {amount} bytes exceeds remaining {self.remaining}"
            )
        self.open[key] = amount
        if declared_size is None:
            self.unknown.add(key)
        self._save()
        return amount

    def settle(self, key: str, bytes_read: int, ok: bool) -> int:
        """Close ``key``'s reservation; returns the bytes charged."""
        if key not in self.open:
            raise ValueError(f"{key!r} has no open reservation")
        amount = self.open.pop(key)
        unknown = key in self.unknown
        self.unknown.discard(key)
        if ok:
            charge = int(bytes_read)
            self.counts["n_charged_ok"] += 1
        elif bytes_read > 0:
            charge = min(amount, int(bytes_read)) if unknown else amount
            self.counts["n_charged_failed"] += 1
        else:
            charge = 0
            self.counts["n_refunded"] += 1
        self.spent += charge
        self._save()
        return charge

    def summary(self) -> dict[str, Any]:
        return {
            "budget_bytes": self.budget_bytes,
            "spent_bytes": self.spent,
            "remaining_bytes": self.remaining,
            **self.counts,
        }

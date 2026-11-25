"""Content-addressed payload store, per-plan receipts and replay (COLLECT §3.5, C17).

Layout under ``<work>/intake/<source>/``:

* ``store/<sha256[:2]>/<sha256>``: verified payloads, mode 0440, shared by every
  plan of the source;
* ``tmp/<sha256 of key>.part``: downloads in flight; stale ones are removed when a
  :class:`Store` starts (a killed job leaves them behind);
* ``<plan_id>/receipts/<sha256 of key>.json``: one receipt per item, written
  atomically, ok or failed, with no local paths in it.

A payload only enters the store after its size and every catalogue digest match.
A mismatch deletes the ``.part``; nothing unverified is ever renamed in.

Replay: an item whose plan already has an ok receipt, or whose catalogue digest
appears in an ok receipt of *any* plan of this source (the cross-plan index), is
served from the store with no network and no charge. NuGet anchors only by SHA512,
so without the index a re-planned run would download everything again.

Before each download the free disk under the intake folder must stay above
``min_free_gib``; otherwise :class:`DiskFloor` stops the pull. A local write that
hits ENOSPC/EDQUOT raises :class:`DiskError` (fatal). Any other unexpected error
after the reservation is settled (refund if no payload byte arrived, else charge)
and recorded as a failed receipt ``internal_<Type>``: one bad item never ends a
leg (review B1, 25 Nov).
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sherlock.collect.http import Fetcher, FetchError, HostTripped, host_of
from sherlock.collect.items import PlanItem
from sherlock.collect.ledger import Ledger

__all__ = [
    "DEFAULT_CONFIG",
    "DiskError",
    "DiskFloor",
    "Receipt",
    "Store",
    "StoreConfig",
]


@dataclass(frozen=True)
class StoreConfig:
    #: Free space (GiB) the intake filesystem keeps; below it the pull stops.
    min_free_gib: float = 50.0


DEFAULT_CONFIG = StoreConfig()


class DiskFloor(Exception):
    """Free disk is below the configured floor."""


class DiskError(Exception):
    """A local write hit ENOSPC/EDQUOT: fatal for the pull, not per item."""


_DISK_FULL = frozenset({errno.ENOSPC, errno.EDQUOT})


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Receipt:
    key: str
    status: str
    expected: Mapping[str, str]
    url: str
    sha256: str | None = None
    size: int | None = None
    final_host: str | None = None
    fetched_at: str | None = None
    error: str | None = None
    #: Bytes the ledger charged for this attempt (0 for replays and refunds).
    charged: int = 0
    #: Not persisted: this call was served from the store.
    replayed: bool = field(default=False, compare=False)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "status": self.status,
            "expected": dict(self.expected),
            "url": self.url,
            "sha256": self.sha256,
            "size": self.size,
            "final_host": self.final_host,
            "fetched_at": self.fetched_at,
            "error": self.error,
            "charged": self.charged,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Receipt:
        return cls(
            key=str(d["key"]),
            status=str(d["status"]),
            expected=dict(d.get("expected") or {}),
            url=str(d.get("url") or ""),
            sha256=d.get("sha256"),
            size=d.get("size"),
            final_host=d.get("final_host"),
            fetched_at=d.get("fetched_at"),
            error=d.get("error"),
            charged=int(d.get("charged") or 0),
        )

    def summary(self) -> dict[str, Any]:
        return {**self.to_dict(), "replayed": self.replayed}


class Store:
    def __init__(
        self,
        work_root: Path,
        source: str,
        config: StoreConfig = DEFAULT_CONFIG,
        *,
        disk_free: Callable[[Path], int] | None = None,
        readonly: bool = False,
    ) -> None:
        """``readonly`` (verify): create nothing and leave stale ``.part`` alone."""
        self.source = source
        self.config = config
        self.root = work_root / "intake" / source
        self.store = self.root / "store"
        self.tmp = self.root / "tmp"
        if not readonly:
            self.store.mkdir(parents=True, exist_ok=True)
            self.tmp.mkdir(parents=True, exist_ok=True)
            for stale in self.tmp.glob("*.part"):
                stale.unlink(missing_ok=True)
        self._disk_free = disk_free or (lambda p: shutil.disk_usage(p).free)
        #: (alg, hex) -> (sha256, size), from ok receipts of every plan.
        self._index: dict[tuple[str, str], tuple[str, int]] = {}
        self._build_index()

    # -- paths ----------------------------------------------------------------
    def path_for(self, sha256: str) -> Path:
        return self.store / sha256[:2] / sha256

    def receipt_path(self, plan_id: str, key: str) -> Path:
        return self.root / plan_id / "receipts" / f"{_key_hash(key)}.json"

    # -- receipts -------------------------------------------------------------
    def _read_receipt(self, path: Path) -> Receipt | None:
        try:
            return Receipt.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write_receipt(self, plan_id: str, r: Receipt) -> None:
        path = self.receipt_path(plan_id, r.key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(r.to_dict(), sort_keys=True) + "\n", "utf-8")
        os.replace(tmp, path)

    def _stored_ok(self, sha256: str | None, size: int | None) -> bool:
        if not sha256:
            return False
        p = self.path_for(sha256)
        try:
            return p.is_file() and (size is None or p.stat().st_size == size)
        except OSError:
            return False

    def _build_index(self) -> None:
        for path in self.root.glob("*/receipts/*.json"):
            r = self._read_receipt(path)
            if r is not None and r.ok and r.sha256 and r.size is not None:
                self._remember(r)

    def _remember(self, r: Receipt) -> None:
        assert r.sha256 is not None and r.size is not None
        for alg, hexd in r.expected.items():
            self._index[(alg, hexd)] = (r.sha256, r.size)

    def valid_receipt(self, plan_id: str, item: PlanItem) -> Receipt | None:
        """The plan's ok receipt for ``item`` if its stored file is present."""
        r = self._read_receipt(self.receipt_path(plan_id, item.key))
        if (
            r is not None
            and r.ok
            and r.key == item.key
            and dict(r.expected) == dict(item.expected)
            and self._stored_ok(r.sha256, r.size)
        ):
            return r
        return None

    def _replay(self, plan_id: str, item: PlanItem) -> Receipt | None:
        r = self.valid_receipt(plan_id, item)
        if r is not None:
            r.replayed = True
            r.charged = 0
            return r
        hits = {self._index.get((a, h)) for a, h in item.expected.items()}
        hits.discard(None)
        if len(hits) != 1:
            return None
        hit = hits.pop()
        assert hit is not None
        sha, size = hit
        if item.size is not None and item.size != size:
            return None
        if not self._stored_ok(sha, size):
            return None
        r = Receipt(
            key=item.key,
            status="ok",
            expected=item.expected,
            url=item.url,
            sha256=sha,
            size=size,
            final_host=None,
            fetched_at=_now(),
            error=None,
            charged=0,
        )
        self._write_receipt(plan_id, r)
        r.replayed = True
        return r

    # -- fetch ----------------------------------------------------------------
    def check_disk(self) -> None:
        free = self._disk_free(self.root)
        if free < self.config.min_free_gib * (1 << 30):
            raise DiskFloor(
                f"free disk {free / (1 << 30):.1f} GiB below the "
                f"{self.config.min_free_gib} GiB floor"
            )

    def fetch_item(
        self, fetcher: Fetcher, ledger: Ledger, item: PlanItem, plan_id: str
    ) -> Receipt:
        """Replay or fetch ``item``. Raises DiskFloor and BudgetExhausted (before
        any request) and lets HostTripped out after recording a failed receipt."""
        replay = self._replay(plan_id, item)
        if replay is not None:
            return replay
        self.check_disk()
        reservation = ledger.reserve(item.key, item.size)
        part = self.tmp / f"{_key_hash(item.key)}.part"
        settled: list[int] = []  # the charge, once settled

        def settle(n: int, ok: bool) -> int:
            if not settled:
                settled.append(ledger.settle(item.key, n, ok=ok))
            return settled[0]

        def part_size() -> int:
            try:
                return part.stat().st_size if part.exists() else 0
            except OSError:
                return 1  # unknown: treat as after payload bytes

        try:
            return self._fetch_reserved(
                item, plan_id, fetcher, reservation, part, settle
            )
        except (HostTripped, DiskError):
            raise
        except Exception as exc:  # noqa: BLE001 - one bad item never ends a leg
            n = part_size()
            part.unlink(missing_ok=True)
            charged = settle(n, False)
            if isinstance(exc, OSError) and exc.errno in _DISK_FULL:
                raise DiskError(
                    f"local disk full ({errno.errorcode[exc.errno]})"
                ) from None
            r = Receipt(
                key=item.key,
                status="failed",
                expected=item.expected,
                url=item.url,
                size=n,
                fetched_at=_now(),
                error=f"internal_{type(exc).__name__}",
                charged=charged,
            )
            try:
                self._write_receipt(plan_id, r)
            except OSError as wexc:
                if wexc.errno in _DISK_FULL:
                    raise DiskError("local disk full while writing a receipt") from None
            return r

    def _fetch_reserved(
        self,
        item: PlanItem,
        plan_id: str,
        fetcher: Fetcher,
        reservation: int,
        part: Path,
        settle: Callable[[int, bool], int],
    ) -> Receipt:
        sha = hashlib.sha256()
        hashers = {"sha256": sha}
        for alg in item.expected:
            if alg != "sha256":
                hashers[alg] = hashlib.new(alg)
        bytes_read = 0
        final_host: str | None = None
        error: str | None = None
        fetch_exc: FetchError | None = None
        try:
            res = fetcher.download(item.url, part, reservation, list(hashers.values()))
            bytes_read = res.bytes_read
            final_host = host_of(res.final_url)
            if item.size is not None and bytes_read != item.size:
                error = "size_mismatch"
            elif any(hashers[a].hexdigest() != h for a, h in item.expected.items()):
                error = "checksum_mismatch"
        except FetchError as exc:
            bytes_read = exc.bytes_read
            error = exc.reason
            fetch_exc = exc
        ok = error is None
        if not ok:
            part.unlink(missing_ok=True)
        charged = settle(bytes_read, ok)
        if not ok:
            r = Receipt(
                key=item.key,
                status="failed",
                expected=item.expected,
                url=item.url,
                size=bytes_read,
                final_host=final_host,
                fetched_at=_now(),
                error=error,
                charged=charged,
            )
            self._write_receipt(plan_id, r)
            if isinstance(fetch_exc, HostTripped):
                raise fetch_exc
            return r
        digest = sha.hexdigest()
        dest = self.path_for(digest)
        if dest.exists():
            part.unlink(missing_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            part.chmod(0o440)
            os.replace(part, dest)
        r = Receipt(
            key=item.key,
            status="ok",
            expected=item.expected,
            url=item.url,
            sha256=digest,
            size=bytes_read,
            final_host=final_host,
            fetched_at=_now(),
            error=None,
            charged=charged,
        )
        self._write_receipt(plan_id, r)
        self._remember(r)
        return r

    # -- verify ---------------------------------------------------------------
    def verify(self, plan_id: str) -> dict[str, Any]:
        """Read-only: re-hash every stored file named by an ok receipt."""
        n_checked = n_missing = n_mismatch = n_bad_receipt = 0
        mismatched: list[str] = []
        for path in sorted((self.root / plan_id / "receipts").glob("*.json")):
            r = self._read_receipt(path)
            if r is None:
                n_bad_receipt += 1
                continue
            if not r.ok or not r.sha256:
                continue
            n_checked += 1
            p = self.path_for(r.sha256)
            if not p.is_file():
                n_missing += 1
                continue
            hs = {"sha256": hashlib.sha256()}
            for a in r.expected:
                hs.setdefault(a, hashlib.new(a))
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    for h in hs.values():
                        h.update(chunk)
            want = {"sha256": r.sha256, **dict(r.expected)}
            if any(hs[a].hexdigest() != h for a, h in want.items()):
                n_mismatch += 1
                mismatched.append(r.key)
        return {
            "plan_id": plan_id,
            "n_checked": n_checked,
            "n_missing": n_missing,
            "n_mismatch": n_mismatch,
            "n_bad_receipt": n_bad_receipt,
            "mismatched_keys": mismatched[:100],
        }

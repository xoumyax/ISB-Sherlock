"""The pull loop for one plan of one source (COLLECT §3.3, C16, C18).

Items go in :func:`~sherlock.collect.plan.order`: the seeded 10% checkpoint sample
first, then the rest. Every item is replayed from the store when a valid receipt
exists, so a killed or requeued job resumes without recharging or duplicating.

C18 auto-continue (brownie is away 25-28 Nov): when the sample is finished the pull
writes ``<plan_id>/checkpoint.json`` (items done, bytes, ok rate, bytes per item,
projected total = spent + declared sizes of the items left + sample mean x items
left of unknown size) and goes on only while the projection fits the budget.
Otherwise it stops with ``stopped='projected_over_budget'``.

Stops (``PullResult.stopped``): ``complete``, ``budget_exhausted``,
``projected_over_budget``, ``checkpoint_no_ok_items``, ``max_items``,
``disk_floor``, ``disk_error``, ``hosts_tripped``. A budget stop is a normal end
(C16: status ok);
``FAILED_STOPS`` (disk, hosts, no ok item in the sample) are not.
An item whose reservation does not fit what is left is skipped
(``dropped['over_remaining_budget']``); the pull stops on budget only when less
than ``min_remaining_bytes`` is left or no later item could fit. One item that
raises unexpectedly is a failure (``internal_<Type>``), never the end of the leg;
a full local disk (``disk_error``) is fatal.
``max_items`` counts network fetches, not replays, so a resumed smoke run still
makes progress.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sherlock.collect.http import Fetcher, HostTripped, host_of
from sherlock.collect.items import PlanItem
from sherlock.collect.ledger import BudgetExhausted, Ledger
from sherlock.collect.plan import Plan, order
from sherlock.collect.store import DiskError, DiskFloor, Receipt, Store

__all__ = ["PullConfig", "PullResult", "Stopped", "pull"]


class Stopped:
    COMPLETE = "complete"
    BUDGET = "budget_exhausted"
    PROJECTED = "projected_over_budget"
    NO_OK = "checkpoint_no_ok_items"
    MAX_ITEMS = "max_items"
    DISK = "disk_floor"
    DISK_ERROR = "disk_error"
    HOSTS = "hosts_tripped"


#: Stops that mean something is wrong rather than a planned end.
FAILED_STOPS = frozenset(
    {Stopped.DISK, Stopped.DISK_ERROR, Stopped.HOSTS, Stopped.NO_OK}
)


@dataclass(frozen=True)
class PullConfig:
    #: Transfer budget for the source, bytes (C13 split).
    budget_bytes: int
    #: Network fetches this invocation (smoke runs); None = no limit.
    max_items: int | None = None
    #: Free-disk floor in GiB (the Store enforces it; recorded here).
    min_free_gib: float = 50.0
    #: Run the C18 checkpoint decision after the sample.
    checkpoint: bool = True
    #: Stop on budget once less than this is left (tiny remainders fit nothing).
    min_remaining_bytes: int = 1 << 20


@dataclass
class PullResult:
    source: str
    plan_id: str
    n_items: int
    n_ok: int = 0
    n_replayed: int = 0
    n_failed: int = 0
    failed: dict[str, int] = field(default_factory=dict)
    #: Items skipped without a request (e.g. over_remaining_budget).
    dropped: dict[str, int] = field(default_factory=dict)
    bytes_fetched: int = 0
    bytes_charged: int = 0
    spent_bytes: int = 0
    budget_bytes: int = 0
    stopped: str = Stopped.COMPLETE
    checkpoint: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "plan_id": self.plan_id,
            "n_items": self.n_items,
            "n_ok": self.n_ok,
            "n_replayed": self.n_replayed,
            "n_failed": self.n_failed,
            "failed": dict(self.failed),
            "dropped": dict(self.dropped),
            "bytes_fetched": self.bytes_fetched,
            "bytes_charged": self.bytes_charged,
            "spent_bytes": self.spent_bytes,
            "budget_bytes": self.budget_bytes,
            "stopped": self.stopped,
            "checkpoint": self.checkpoint,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> PullResult:
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})

    def summary(self) -> dict[str, Any]:
        out = self.to_dict()
        out["checkpoint_decision"] = (self.checkpoint or {}).get("decision")
        out.pop("checkpoint")
        return out


def _write_json(path: Any, body: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(body, indent=1, sort_keys=True) + "\n", "utf-8")
    os.replace(tmp, path)


def pull(
    plan: Plan,
    fetcher: Fetcher,
    ledger: Ledger,
    store: Store,
    config: PullConfig,
    *,
    on_event: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> PullResult:
    def event(kind: str, **data: Any) -> None:
        if on_event is not None:
            on_event(kind, data)

    ledger.set_budget(config.budget_bytes)
    items, n_ck = order(plan)
    plan_hosts = {host_of(i.url) for i in items}
    res = PullResult(
        source=plan.source,
        plan_id=plan.plan_id,
        n_items=len(items),
        budget_bytes=config.budget_bytes,
    )
    unknown_cost = ledger.config.unknown_size_reserve_bytes

    def cost(i: PlanItem) -> int:
        return unknown_cost if i.size is None else i.size

    # suffix minimum of reservation sizes: what the cheapest later item needs
    suffix_min = [0] * (len(items) + 1)
    suffix_min[len(items)] = 1 << 62
    for k in range(len(items) - 1, -1, -1):
        suffix_min[k] = min(cost(items[k]), suffix_min[k + 1])
    ck_bytes = ck_ok = ck_done = 0
    n_fetches = 0
    stopped = Stopped.COMPLETE

    def fail(reason: str) -> None:
        res.n_failed += 1
        res.failed[reason] = res.failed.get(reason, 0) + 1

    for idx, item in enumerate(items):
        is_ck = idx < n_ck
        if config.max_items is not None and n_fetches >= config.max_items:
            if store.valid_receipt(plan.plan_id, item) is None:
                stopped = Stopped.MAX_ITEMS
                break
        r: Receipt | None = None
        try:
            r = store.fetch_item(fetcher, ledger, item, plan.plan_id)
        except BudgetExhausted:
            left = ledger.remaining
            if left < config.min_remaining_bytes or left < suffix_min[idx + 1]:
                stopped = Stopped.BUDGET
                break
            res.dropped["over_remaining_budget"] = (
                res.dropped.get("over_remaining_budget", 0) + 1
            )
            event(
                "item",
                key=item.key,
                status="skipped",
                error="over_remaining_budget",
                replayed=False,
            )
        except DiskFloor:
            stopped = Stopped.DISK
            break
        except DiskError:
            stopped = Stopped.DISK_ERROR
            break
        except HostTripped:
            n_fetches += 1
            fail("host_tripped")
            if plan_hosts <= fetcher.tripped_hosts:
                stopped = Stopped.HOSTS
                break
        except Exception as exc:  # noqa: BLE001 - one bad item never ends a leg
            fail(f"internal_{type(exc).__name__}")
            event(
                "item",
                key=item.key,
                status="failed",
                error=f"internal_{type(exc).__name__}",
                replayed=False,
            )
        if r is not None:
            if not r.replayed:
                n_fetches += 1
                res.bytes_charged += r.charged
            if r.ok:
                if r.replayed:
                    res.n_replayed += 1
                else:
                    res.n_ok += 1
                    res.bytes_fetched += r.size or 0
            else:
                fail(r.error or "unknown")
            event(
                "item",
                key=item.key,
                status=r.status,
                error=r.error,
                replayed=r.replayed,
            )
        if is_ck:
            ck_done += 1
            if r is not None:
                ck_bytes += (r.size or 0) if r.ok else r.charged
                ck_ok += int(r.ok)
        if config.checkpoint and is_ck and idx == n_ck - 1:
            rest = [
                i for i in items[n_ck:] if store.valid_receipt(plan.plan_id, i) is None
            ]
            left = len(rest)
            n_unknown = sum(1 for i in rest if i.size is None)
            declared_left = sum(i.size for i in rest if i.size is not None)
            per_item = ck_bytes / ck_done if ck_done else 0.0
            # declared sizes where known; the sample mean only for unknown ones
            projected = ledger.spent + declared_left + per_item * n_unknown
            if ck_ok == 0:
                decision = "stop"
                why = Stopped.NO_OK
            elif projected > config.budget_bytes:
                decision, why = "stop", Stopped.PROJECTED
            else:
                decision, why = "continue", ""
            ck = {
                "plan_id": plan.plan_id,
                "written_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "n_items": ck_done,
                "n_ok": ck_ok,
                "ok_rate": ck_ok / ck_done if ck_done else 0.0,
                "bytes": ck_bytes,
                "bytes_per_item": per_item,
                "bytes_per_ok_item": ck_bytes / ck_ok if ck_ok else None,
                "spent_bytes": ledger.spent,
                "items_left": left,
                "n_unknown_left": n_unknown,
                "declared_bytes_left": declared_left,
                "projected_total_bytes": int(projected),
                "budget_bytes": config.budget_bytes,
                "decision": decision,
            }
            _write_json(store.root / plan.plan_id / "checkpoint.json", ck)
            res.checkpoint = ck
            event("checkpoint", **ck)
            if decision == "stop":
                stopped = why
                break

    res.stopped = stopped
    res.spent_bytes = ledger.spent
    return res

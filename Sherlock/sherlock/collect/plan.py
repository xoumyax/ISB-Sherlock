"""The frozen plan: what one pull of one source will fetch, fixed before it starts.

COLLECT §3.1. A planner's :class:`~sherlock.collect.items.CatalogResult` becomes a
:class:`Plan` with a stable ``plan_id = <source>-<YYYYMMDD>-<plan_sha256[:12]>``.
``plan_sha256`` is the sha256 of canonical JSON of the items and the anchor
digests, so the same catalogue on the same day gives the same id. The seed is kept
beside the hash (it decides the order, not the content).

On disk: ``<intake>/<source>/<plan_id>/plan.json`` plus ``anchors/<safe name>``,
the exact catalogue bytes. :func:`load_plan` re-checks the hash and every anchor
digest, so a resume never runs from an edited plan.

:func:`order` puts a seeded random 10% (ceil, at least one) first: the C18
checkpoint sample, representative of the plan rather than its alphabetical head.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sherlock.collect.items import CatalogResult, PlanItem

__all__ = [
    "CHECKPOINT_FRACTION",
    "Plan",
    "load_plan",
    "make_plan",
    "order",
    "plan_dir",
    "write_plan",
]

#: Share of a plan fetched first as the checkpoint sample (C18).
CHECKPOINT_FRACTION = 0.1

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_ID = re.compile(r"^[a-z0-9]+-\d{8}-[0-9a-f]{12}$")


def _canon(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _digests(anchors: Mapping[str, bytes]) -> dict[str, str]:
    return {k: hashlib.sha256(v).hexdigest() for k, v in sorted(anchors.items())}


def _plan_sha256(items: tuple[PlanItem, ...], anchors: Mapping[str, bytes]) -> str:
    body = {"items": [i.to_dict() for i in items], "anchors": _digests(anchors)}
    return hashlib.sha256(_canon(body)).hexdigest()


@dataclass(frozen=True)
class Plan:
    source: str
    plan_id: str
    plan_sha256: str
    created_at: str
    seed: int
    items: tuple[PlanItem, ...]
    anchors: Mapping[str, bytes] = field(default_factory=dict)
    #: Planner drop counts and stats, kept for the record (not hashed).
    dropped: Mapping[str, int] = field(default_factory=dict)
    stats: Mapping[str, Any] = field(default_factory=dict)
    #: Planner parameters (e.g. plan_limit), kept so a resume can match them.
    params: Mapping[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        known = [i.size for i in self.items if i.size is not None]
        return {
            "source": self.source,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "seed": self.seed,
            "n_items": len(self.items),
            "n_unknown_size": len(self.items) - len(known),
            "declared_bytes": sum(known),
            "n_anchors": len(self.anchors),
            "dropped": dict(self.dropped),
        }


def make_plan(
    result: CatalogResult,
    seed: int,
    created_at: datetime | None = None,
    params: Mapping[str, Any] | None = None,
) -> Plan:
    created = (created_at or datetime.now(UTC)).astimezone(UTC)
    items = tuple(result.items)
    sha = _plan_sha256(items, result.anchors)
    return Plan(
        source=result.source,
        plan_id=f"{result.source}-{created:%Y%m%d}-{sha[:12]}",
        plan_sha256=sha,
        created_at=created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        seed=int(seed),
        items=items,
        anchors=dict(result.anchors),
        dropped=dict(result.dropped),
        stats=dict(result.stats),
        params=dict(params or {}),
    )


def plan_dir(intake: Path, source: str, plan_id: str) -> Path:
    if not _ID.match(plan_id) or not plan_id.startswith(f"{source}-"):
        raise ValueError(f"{plan_id!r} is not a plan id of source {source!r}")
    return intake / source / plan_id


def _anchor_files(anchors: Mapping[str, bytes]) -> dict[str, str]:
    out: dict[str, str] = {}
    used: set[str] = set()
    for i, name in enumerate(sorted(anchors)):
        safe = _SAFE.sub("_", name).strip("._") or "anchor"
        safe = safe[:100]
        if safe in used:
            safe = f"{i:04d}_{safe}"
        used.add(safe)
        out[name] = safe
    return out


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def write_plan(plan: Plan, intake: Path) -> Path:
    """Write ``plan`` under ``intake``; idempotent for the same plan and seed."""
    d = plan_dir(intake, plan.source, plan.plan_id)
    if (d / "plan.json").is_file():
        old = load_plan(intake, plan.source, plan.plan_id)
        if old.plan_sha256 != plan.plan_sha256 or old.seed != plan.seed:
            raise ValueError(
                f"{plan.plan_id} already exists with another hash or seed; "
                "plans are frozen: use the existing one or a new seed/day"
            )
        return d
    (d / "anchors").mkdir(parents=True, exist_ok=True)
    files = _anchor_files(plan.anchors)
    for name, data in plan.anchors.items():
        _atomic_write(d / "anchors" / files[name], data)
    body = {
        "source": plan.source,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "created_at": plan.created_at,
        "seed": plan.seed,
        "params": dict(plan.params),
        "anchors": {
            name: {
                "file": files[name],
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for name, data in sorted(plan.anchors.items())
        },
        "dropped": dict(plan.dropped),
        "stats": dict(plan.stats),
        "items": [i.to_dict() for i in plan.items],
    }
    _atomic_write(
        d / "plan.json", (json.dumps(body, indent=1, sort_keys=True) + "\n").encode()
    )
    return d


def load_plan(intake: Path, source: str, plan_id: str) -> Plan:
    """Reload a plan, re-verifying its hash and every anchor's digest."""
    d = plan_dir(intake, source, plan_id)
    body = json.loads((d / "plan.json").read_text(encoding="utf-8"))
    anchors: dict[str, bytes] = {}
    for name, meta in body.get("anchors", {}).items():
        fname = str(meta["file"])
        if "/" in fname or fname.startswith("."):
            raise ValueError(f"anchor file name {fname!r} is not safe")
        data = (d / "anchors" / fname).read_bytes()
        if hashlib.sha256(data).hexdigest() != meta["sha256"]:
            raise ValueError(f"anchor {name!r} does not match its recorded digest")
        anchors[name] = data
    items = tuple(PlanItem.from_dict(x) for x in body["items"])
    sha = _plan_sha256(items, anchors)
    if sha != body["plan_sha256"] or not plan_id.endswith(sha[:12]):
        raise ValueError(f"{plan_id}: plan_sha256 does not match its contents")
    if body["source"] != source or body["plan_id"] != plan_id:
        raise ValueError(f"{plan_id}: plan.json names another source or id")
    return Plan(
        source=source,
        plan_id=plan_id,
        plan_sha256=sha,
        created_at=body["created_at"],
        seed=int(body["seed"]),
        items=items,
        anchors=anchors,
        dropped=dict(body.get("dropped") or {}),
        stats=dict(body.get("stats") or {}),
        params=dict(body.get("params") or {}),
    )


def order(
    plan: Plan, fraction: float = CHECKPOINT_FRACTION
) -> tuple[tuple[PlanItem, ...], int]:
    """Seeded fetch order and the size of its leading checkpoint sample."""
    items = sorted(plan.items, key=lambda i: i.key)
    random.Random(f"{plan.seed}:order").shuffle(items)
    n_ck = max(1, math.ceil(round(fraction * len(items), 9))) if items else 0
    return tuple(items), n_ck

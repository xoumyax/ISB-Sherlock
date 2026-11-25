"""L18: the plan is frozen and reloaded, never recomputed on resume.

A resume that re-reads a moving catalogue fetches a different set and mixes two
populations. Sherlock writes the plan once (items, anchors, seed, plan_sha256)
and a resume reloads it, refusing one whose contents no longer match the hash.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from sherlock.collect.items import CatalogResult, PlanItem
from sherlock.collect.plan import load_plan, make_plan, write_plan


def test_plan_frozen_and_reloaded(tmp_path) -> None:
    item = PlanItem(
        source="nuget",
        key="nuget:a/1",
        url="https://x.test/a",
        expected={"sha512": "ab" * 64},
        size=1,
    )
    res = CatalogResult(source="nuget", items=(item,), anchors={"index.json": b"{}"})
    plan = make_plan(res, seed=1, created_at=datetime(2026, 11, 25, tzinfo=UTC))
    d = write_plan(plan, tmp_path)
    again = load_plan(tmp_path, "nuget", plan.plan_id)
    assert again.items == plan.items and again.plan_sha256 == plan.plan_sha256
    body = json.loads((d / "plan.json").read_text())
    body["items"][0]["url"] = "https://x.test/other"
    (d / "plan.json").write_text(json.dumps(body))
    with pytest.raises(ValueError, match="plan_sha256"):
        load_plan(tmp_path, "nuget", plan.plan_id)

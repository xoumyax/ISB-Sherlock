"""The frozen plan: id, hash, anchors on disk, reload checks, seeded order."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from sherlock.collect.items import CatalogResult, PlanItem
from sherlock.collect.plan import Plan, load_plan, make_plan, order, write_plan

_T = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)


def _items(n):
    return tuple(
        PlanItem(
            source="nuget",
            key=f"nuget:pkg{i:03d}/1.0.0",
            url=f"https://api.example.test/pkg{i:03d}.nupkg",
            expected={"sha512": f"{i:02x}" * 64},
            size=100 + i,
        )
        for i in range(n)
    )


def _result(n=5):
    return CatalogResult(
        source="nuget",
        items=_items(n),
        anchors={"search/page-0.json": b'{"data":[]}', "index.json": b"{}"},
        dropped={"x": 1},
    )


def test_plan_id_shape_and_determinism():
    a = make_plan(_result(), seed=7, created_at=_T)
    b = make_plan(_result(), seed=7, created_at=_T)
    assert a.plan_id == b.plan_id
    assert a.plan_id.startswith("nuget-20261125-")
    assert a.plan_id.endswith(a.plan_sha256[:12])
    c = make_plan(_result(6), seed=7, created_at=_T)
    assert c.plan_sha256 != a.plan_sha256


def test_plan_frozen_and_reloaded(tmp_path):
    p = make_plan(_result(), seed=7, created_at=_T)
    d = write_plan(p, tmp_path)
    assert d == tmp_path / "nuget" / p.plan_id
    assert (d / "plan.json").is_file()
    assert len(list((d / "anchors").iterdir())) == 2
    q = load_plan(tmp_path, "nuget", p.plan_id)
    assert q.items == p.items and q.anchors == p.anchors and q.seed == 7
    assert q.plan_sha256 == p.plan_sha256
    with pytest.raises(AttributeError):
        q.seed = 3  # type: ignore[misc]
    # rewriting the same plan is idempotent
    assert write_plan(p, tmp_path) == d


def test_tampered_plan_or_anchor_refused(tmp_path):
    p = make_plan(_result(), seed=7, created_at=_T)
    d = write_plan(p, tmp_path)
    anchor = next((d / "anchors").iterdir())
    anchor.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="anchor"):
        load_plan(tmp_path, "nuget", p.plan_id)
    p2 = make_plan(_result(), seed=7, created_at=_T)
    d2 = write_plan(p2, tmp_path / "b")
    j = json.loads((d2 / "plan.json").read_text())
    j["items"][0]["size"] = 1
    (d2 / "plan.json").write_text(json.dumps(j))
    with pytest.raises(ValueError, match="plan_sha256"):
        load_plan(tmp_path / "b", "nuget", p.plan_id)


def test_existing_plan_with_other_seed_refused(tmp_path):
    p = make_plan(_result(), seed=7, created_at=_T)
    write_plan(p, tmp_path)
    other = Plan(**{**p.__dict__, "seed": 8})
    with pytest.raises(ValueError):
        write_plan(other, tmp_path)


def test_anchor_names_made_safe(tmp_path):
    r = CatalogResult(
        source="nuget", items=_items(1), anchors={"../../etc/passwd": b"x"}
    )
    p = make_plan(r, seed=1, created_at=_T)
    d = write_plan(p, tmp_path)
    files = list((d / "anchors").iterdir())
    assert len(files) == 1 and ".." not in files[0].name
    assert load_plan(tmp_path, "nuget", p.plan_id).anchors == {"../../etc/passwd": b"x"}


def test_checkpoint_is_seeded_random_sample():
    p = make_plan(_result(40), seed=7, created_at=_T)
    items, n_ck = order(p)
    assert n_ck == 4
    assert sorted(i.key for i in items) == sorted(i.key for i in p.items)
    head = [i.key for i in items[:n_ck]]
    assert head != [i.key for i in p.items[:n_ck]]  # not the plan's head
    again, _ = order(make_plan(_result(40), seed=7, created_at=_T))
    assert [i.key for i in again] == [i.key for i in items]
    other, _ = order(make_plan(_result(40), seed=8, created_at=_T))
    assert [i.key for i in other] != [i.key for i in items]


def test_checkpoint_at_least_one_and_ceil():
    assert order(make_plan(_result(1), seed=1, created_at=_T))[1] == 1
    assert order(make_plan(_result(11), seed=1, created_at=_T))[1] == 2

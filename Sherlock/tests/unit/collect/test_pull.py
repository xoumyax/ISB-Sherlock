"""The pull loop: order, resume, stops, and the C18 auto-continue checkpoint."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sherlock.collect.http import Fetcher, HttpConfig, MockResponse, MockTransport
from sherlock.collect.items import CatalogResult, PlanItem
from sherlock.collect.ledger import Ledger
from sherlock.collect.plan import make_plan, write_plan
from sherlock.collect.pull import PullConfig, PullResult, pull
from sherlock.collect.store import Store, StoreConfig

_T = datetime(2026, 11, 25, tzinfo=UTC)


def _catalog(n, size=1000, bad=()):
    items, routes = [], {}
    for i in range(n):
        body = bytes([i % 256]) * size + f"pkg{i}".encode()
        url = f"https://api.example.test/p/{i}.nupkg"
        exp = hashlib.sha512(body).hexdigest() if i not in bad else "ab" * 64
        items.append(
            PlanItem(
                source="nuget",
                key=f"nuget:p{i:03d}/1.0",
                url=url,
                expected={"sha512": exp},
                size=len(body),
            )
        )
        routes[url] = MockResponse(200, body)
    return CatalogResult(source="nuget", items=tuple(items)), routes


def _env(tmp_path, n=20, budget=10**7, free=10**15, bad=(), routes=None, **http):
    res, r = _catalog(n, bad=bad)
    plan = make_plan(res, seed=3, created_at=_T)
    work = tmp_path / "work"
    write_plan(plan, work / "intake")
    t = MockTransport(routes if routes is not None else r)
    cfg = HttpConfig(min_interval_s=0, **http)
    f = Fetcher(t, cfg, clock=lambda: 0.0, sleep=lambda s: None)
    store = Store(work, "nuget", StoreConfig(min_free_gib=1), disk_free=lambda p: free)
    led = Ledger(work / "intake" / "nuget" / "ledger.json", budget)
    return plan, t, f, store, led, work


def test_pull_completes_and_writes_checkpoint(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7))
    assert res.stopped == "complete" and res.n_ok == 20 and res.n_failed == 0
    ck = json.loads(
        (work / "intake" / "nuget" / plan.plan_id / "checkpoint.json").read_text()
    )
    assert ck["n_items"] == 2 and ck["decision"] == "continue"
    assert ck["projected_total_bytes"] <= 10**7
    assert PullResult.from_dict(res.to_dict()) == res
    assert res.summary()["stopped"] == "complete"


def test_auto_continue_stops_when_projected_over_budget(tmp_path):
    # 20 items of ~1 KB: projected ~20 KB; budget 5 KB is enough for the sample
    plan, t, f, store, led, work = _env(tmp_path)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=5000))
    assert res.stopped == "projected_over_budget"
    assert res.n_ok == 2
    ck = json.loads(
        (work / "intake" / "nuget" / plan.plan_id / "checkpoint.json").read_text()
    )
    assert ck["decision"] == "stop" and ck["projected_total_bytes"] > 5000


def test_budget_exhausted_stops(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=1500, checkpoint=False))
    assert res.stopped == "budget_exhausted" and res.n_ok == 1


def test_max_items_stops(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7, max_items=3))
    assert res.stopped == "max_items" and res.n_ok == 3


def test_disk_floor_stops(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path, free=0)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7))
    assert res.stopped == "disk_floor" and t.calls == []


def test_all_hosts_tripped_stops(tmp_path):
    plan, t, f, store, led, work = _env(
        tmp_path, routes={}, breaker_consecutive_failures=3, max_retries=0
    )
    t.routes = {i.url: MockResponse(503) for i in plan.items}
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7, checkpoint=False))
    assert res.stopped == "hosts_tripped"
    assert len(t.calls) == 3


def test_failures_counted_by_reason(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path, n=10, bad=(1, 2))
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7, checkpoint=False))
    assert res.n_ok == 8 and res.failed == {"checksum_mismatch": 2}


def test_resume_does_not_recharge_or_duplicate_rows(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path)
    first = pull(plan, f, led, store, PullConfig(budget_bytes=10**7, max_items=5))
    spent, calls = led.spent, len(t.calls)
    # new process: fresh store and ledger objects
    store2 = Store(
        work, "nuget", StoreConfig(min_free_gib=1), disk_free=lambda p: 10**15
    )
    led2 = Ledger(work / "intake" / "nuget" / "ledger.json", 10**7)
    second = pull(plan, f, led2, store2, PullConfig(budget_bytes=10**7))
    assert first.n_ok == 5
    assert second.n_replayed == 5 and second.n_ok == 15
    assert led2.spent == spent + sum(i.size for i in plan.items) - spent
    assert len(t.calls) == calls + 15
    receipts = list((work / "intake" / "nuget" / plan.plan_id / "receipts").iterdir())
    assert len(receipts) == 20
    assert (
        sum(1 for _ in (work / "intake" / "nuget" / "store").rglob("*") if _.is_file())
        == 20
    )


def test_checkpoint_with_no_ok_items_stops(tmp_path):
    plan, t, f, store, led, work = _env(tmp_path, n=5, bad=range(5))
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7))
    assert res.stopped == "checkpoint_no_ok_items" and res.n_failed == 1


def _sized_plan(tmp_path, sizes):
    items, routes = [], {}
    for i, size in enumerate(sizes):
        body = bytes([i]) * size
        url = f"https://api.example.test/p/{i}.nupkg"
        items.append(
            PlanItem(
                source="nuget",
                key=f"nuget:s{i:03d}/1.0",
                url=url,
                expected={"sha512": hashlib.sha512(body).hexdigest()},
                size=None if size == 0 else size,
            )
        )
        routes[url] = MockResponse(200, body)
    plan = make_plan(
        CatalogResult(source="nuget", items=tuple(items)), seed=3, created_at=_T
    )
    work = tmp_path / "work"
    write_plan(plan, work / "intake")
    t = MockTransport(routes)
    f = Fetcher(
        t, HttpConfig(min_interval_s=0), clock=lambda: 0.0, sleep=lambda s: None
    )
    store = Store(
        work, "nuget", StoreConfig(min_free_gib=1), disk_free=lambda p: 10**15
    )
    return plan, t, f, store, work


def test_over_budget_item_skipped_and_smaller_ones_continue(tmp_path):
    from sherlock.collect.plan import order

    sizes = [100] * 9 + [5000]
    plan, t, f, store, work = _sized_plan(tmp_path, sizes)
    led = Ledger(work / "intake" / "nuget" / "ledger.json", 1500)
    res = pull(
        plan,
        f,
        led,
        store,
        PullConfig(budget_bytes=1500, checkpoint=False, min_remaining_bytes=0),
    )
    assert res.dropped == {"over_remaining_budget": 1}
    assert res.n_ok == 9 and res.stopped == "complete"
    items, _ = order(plan)
    assert items  # order is seeded; the big one may sit anywhere


def test_budget_stop_when_nothing_left_fits(tmp_path):
    plan, t, f, store, work = _sized_plan(tmp_path, [1000] * 5)
    led = Ledger(work / "intake" / "nuget" / "ledger.json", 2500)
    res = pull(
        plan,
        f,
        led,
        store,
        PullConfig(budget_bytes=2500, checkpoint=False, min_remaining_bytes=0),
    )
    assert res.n_ok == 2 and res.stopped == "budget_exhausted"
    assert len(t.calls) == 2


def test_projection_uses_declared_sizes(tmp_path):
    # sample items are small, the rest are large: the mean would under-project
    sizes = [10] * 10 + [10_000] * 10
    plan, t, f, store, work = _sized_plan(tmp_path, sizes)
    led = Ledger(work / "intake" / "nuget" / "ledger.json", 50_000)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=50_000))
    ck = res.checkpoint
    remaining_declared = sum(sizes) - ck["bytes"]
    assert ck["projected_total_bytes"] == ck["spent_bytes"] + remaining_declared
    assert ck["decision"] == "stop" and res.stopped == "projected_over_budget"


def test_projection_mixes_declared_and_mean_for_unknown(tmp_path):
    sizes = [100] * 9 + [0]  # one unknown size
    plan, t, f, store, work = _sized_plan(tmp_path, sizes)
    led = Ledger(work / "intake" / "nuget" / "ledger.json", 10**6)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**6))
    ck = res.checkpoint
    assert ck["n_unknown_left"] in (0, 1)
    known_left = ck["items_left"] - ck["n_unknown_left"]
    exp = (
        ck["spent_bytes"]
        + 100 * known_left
        + int(ck["bytes_per_item"] * ck["n_unknown_left"])
    )
    assert abs(ck["projected_total_bytes"] - exp) <= 1


def test_one_bad_item_never_ends_the_leg(tmp_path, monkeypatch):
    plan, t, f, store, led, work = _env(tmp_path, n=6)
    real = store.fetch_item
    bad = plan.items[2].key

    def flaky(fetcher, ledger, item, plan_id):
        if item.key == bad:
            raise RuntimeError("bug")
        return real(fetcher, ledger, item, plan_id)

    monkeypatch.setattr(store, "fetch_item", flaky)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7, checkpoint=False))
    assert res.n_ok == 5 and res.failed == {"internal_RuntimeError": 1}
    assert res.stopped == "complete"


def test_disk_error_is_a_failed_stop(tmp_path, monkeypatch):
    from sherlock.collect.pull import FAILED_STOPS
    from sherlock.collect.store import DiskError

    plan, t, f, store, led, work = _env(tmp_path, n=3)

    def full(*a, **k):
        raise DiskError("full")

    monkeypatch.setattr(store, "fetch_item", full)
    res = pull(plan, f, led, store, PullConfig(budget_bytes=10**7))
    assert res.stopped == "disk_error" and "disk_error" in FAILED_STOPS

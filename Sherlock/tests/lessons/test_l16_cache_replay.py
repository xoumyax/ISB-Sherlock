"""L16: cache replay spends nothing.

The V1-era fetch kit re-reserved budget for files it already held, so a resumed
pull paid twice. Sherlock replays a verified payload from the store with no
network request and no ledger charge, within a plan and across plans.
"""

from __future__ import annotations

import hashlib

from sherlock.collect.http import Fetcher, HttpConfig, MockResponse, MockTransport
from sherlock.collect.items import PlanItem
from sherlock.collect.ledger import Ledger
from sherlock.collect.store import Store, StoreConfig

BODY = b"synthetic payload" * 50
URL = "https://api.example.test/a.nupkg"


def test_cache_replay_spends_no_budget(tmp_path) -> None:
    t = MockTransport({URL: MockResponse(200, BODY)})
    f = Fetcher(
        t, HttpConfig(min_interval_s=0), clock=lambda: 0.0, sleep=lambda s: None
    )
    work = tmp_path / "work"
    led = Ledger(work / "intake" / "nuget" / "ledger.json", 10**6)
    item = PlanItem(
        source="nuget",
        key="nuget:a/1",
        url=URL,
        expected={"sha512": hashlib.sha512(BODY).hexdigest()},
        size=len(BODY),
    )
    store = Store(work, "nuget", StoreConfig(min_free_gib=0), disk_free=lambda p: 1)
    store.fetch_item(f, led, item, "nuget-20261125-aaaaaaaaaaaa")
    spent, calls = led.spent, len(t.calls)
    for plan_id in ("nuget-20261125-aaaaaaaaaaaa", "nuget-20261126-bbbbbbbbbbbb"):
        fresh = Store(work, "nuget", StoreConfig(min_free_gib=0), disk_free=lambda p: 1)
        r = fresh.fetch_item(f, led, item, plan_id)
        assert r.ok and r.replayed and r.charged == 0
    assert led.spent == spent and len(t.calls) == calls

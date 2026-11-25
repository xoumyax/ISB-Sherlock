"""The content-addressed store, receipts and replay."""

from __future__ import annotations

import base64
import hashlib
import json
import stat

import pytest

from sherlock.collect.http import Fetcher, HttpConfig, MockResponse, MockTransport
from sherlock.collect.items import PlanItem
from sherlock.collect.ledger import Ledger
from sherlock.collect.store import DiskFloor, Store, StoreConfig

BODY = b"MZ" + b"\x00" * 500 + b"synthetic nupkg"
SHA256 = hashlib.sha256(BODY).hexdigest()
SHA512 = hashlib.sha512(BODY).hexdigest()
URL = "https://api.example.test/p/a.nupkg"


def _item(**kw):
    base = dict(
        source="nuget",
        key="nuget:a/1.0.0",
        url=URL,
        expected={"sha512": SHA512},
        size=len(BODY),
    )
    base.update(kw)
    return PlanItem(**base)


def _setup(tmp_path, routes=None, budget=10**6, free=10**15):
    t = MockTransport(routes if routes is not None else {URL: MockResponse(200, BODY)})
    f = Fetcher(
        t, HttpConfig(min_interval_s=0), clock=lambda: 0.0, sleep=lambda s: None
    )
    work = tmp_path / "work"
    store = Store(work, "nuget", StoreConfig(min_free_gib=1), disk_free=lambda p: free)
    led = Ledger(work / "intake" / "nuget" / "ledger.json", budget)
    return t, f, store, led


def test_success_stores_readonly_with_receipt(tmp_path):
    t, f, store, led = _setup(tmp_path)
    r = store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "ok" and r.sha256 == SHA256 and not r.replayed
    p = store.path_for(SHA256)
    assert p.read_bytes() == BODY
    assert stat.S_IMODE(p.stat().st_mode) == 0o440
    assert p.parent.name == SHA256[:2]
    rec = json.loads(
        store.receipt_path("nuget-20261125-aaaaaaaaaaaa", "nuget:a/1.0.0").read_text()
    )
    assert rec["status"] == "ok" and rec["final_host"] == "api.example.test"
    assert rec["fetched_at"].endswith("Z")
    assert led.spent == len(BODY)
    assert list(store.tmp.iterdir()) == []


def test_checksum_mismatch_rejects(tmp_path):
    t, f, store, led = _setup(tmp_path)
    bad = _item(expected={"sha512": "ab" * 64})
    r = store.fetch_item(f, led, bad, "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "failed" and r.error == "checksum_mismatch"
    assert not store.path_for(SHA256).exists()
    assert list(store.tmp.iterdir()) == []
    assert led.spent == len(BODY)  # bytes moved: charged


def test_nuget_base64_sha512_verified(tmp_path):
    b64 = base64.b64encode(hashlib.sha512(BODY).digest()).decode()
    hexd = base64.b64decode(b64).hex()
    t, f, store, led = _setup(tmp_path)
    r = store.fetch_item(
        f, led, _item(expected={"sha512": hexd}), "nuget-20261125-aaaaaaaaaaaa"
    )
    assert r.status == "ok"


def test_size_mismatch_rejects(tmp_path):
    t, f, store, led = _setup(tmp_path)
    r = store.fetch_item(
        f, led, _item(size=len(BODY) + 10), "nuget-20261125-aaaaaaaaaaaa"
    )
    assert r.status == "failed" and r.error == "size_mismatch"
    assert not store.path_for(SHA256).exists()


def test_cache_replay_spends_no_budget(tmp_path):
    t, f, store, led = _setup(tmp_path)
    pid = "nuget-20261125-aaaaaaaaaaaa"
    store.fetch_item(f, led, _item(), pid)
    spent, calls = led.spent, len(t.calls)
    r = store.fetch_item(f, led, _item(), pid)
    assert r.replayed and r.status == "ok"
    assert led.spent == spent and len(t.calls) == calls


def test_cross_plan_replay_via_digest_index(tmp_path):
    t, f, store, led = _setup(tmp_path)
    store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    spent, calls = led.spent, len(t.calls)
    # a fresh Store (new process) and a new plan id: still no network, no charge
    store2 = Store(
        tmp_path / "work",
        "nuget",
        StoreConfig(min_free_gib=1),
        disk_free=lambda p: 10**15,
    )
    r = store2.fetch_item(f, led, _item(), "nuget-20261126-bbbbbbbbbbbb")
    assert r.replayed and r.sha256 == SHA256
    assert led.spent == spent and len(t.calls) == calls
    assert store2.receipt_path("nuget-20261126-bbbbbbbbbbbb", "nuget:a/1.0.0").is_file()


def test_refund_only_pre_payload_failures(tmp_path):
    t, f, store, led = _setup(tmp_path, routes={URL: MockResponse(404)})
    r = store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "failed" and r.error == "http_404"
    assert led.spent == 0


def test_partial_body_charges_reservation(tmp_path):
    routes = {URL: MockResponse(200, BODY, chunk=100, fail_after=200)}
    t, f, store, led = _setup(tmp_path, routes=routes)
    r = store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "failed" and r.error == "connection_error"
    assert led.spent == len(BODY)  # the whole reservation
    assert list(store.tmp.iterdir()) == []


def test_unknown_size_overrun_aborts(tmp_path):
    big = b"x" * 5000
    routes = {URL: MockResponse(200, big, {"content-length": ""}, chunk=512)}
    t, f, store, led = _setup(tmp_path, routes=routes, budget=10**6)
    led.config = type(led.config)(unknown_size_reserve_bytes=1000)
    item = _item(size=None, expected={"sha256": hashlib.sha256(big).hexdigest()})
    r = store.fetch_item(f, led, item, "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "failed" and r.error == "too_large"
    assert led.spent == 1000
    assert not store.path_for(hashlib.sha256(big).hexdigest()).exists()


def test_disk_floor_raises_before_network(tmp_path):
    t, f, store, led = _setup(tmp_path, free=10)
    with pytest.raises(DiskFloor):
        store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert t.calls == [] and led.spent == 0


def test_stale_part_removed_on_start(tmp_path):
    tmp = tmp_path / "work" / "intake" / "nuget" / "tmp"
    tmp.mkdir(parents=True)
    (tmp / "old.part").write_bytes(b"x")
    Store(tmp_path / "work", "nuget")
    assert not (tmp / "old.part").exists()


def test_corrupt_receipt_treated_as_absent(tmp_path):
    t, f, store, led = _setup(tmp_path)
    pid = "nuget-20261125-aaaaaaaaaaaa"
    store.fetch_item(f, led, _item(), pid)
    store.receipt_path(pid, "nuget:a/1.0.0").write_text("{not json")
    store2 = Store(
        tmp_path / "work",
        "nuget",
        StoreConfig(min_free_gib=1),
        disk_free=lambda p: 10**15,
    )
    # the stored file still replays through... nothing (index built from receipts)
    r = store2.fetch_item(f, led, _item(), pid)
    assert r.status == "ok"


def test_verify_detects_tampered_store_file(tmp_path):
    t, f, store, led = _setup(tmp_path)
    pid = "nuget-20261125-aaaaaaaaaaaa"
    store.fetch_item(f, led, _item(), pid)
    p = store.path_for(SHA256)
    p.chmod(0o640)
    p.write_bytes(b"tampered")
    v = store.verify(pid)
    assert v["n_checked"] == 1 and v["n_mismatch"] == 1


def test_declared_oversize_refused_and_refunded(tmp_path):
    routes = {URL: MockResponse(200, BODY + b"extra")}
    t, f, store, led = _setup(tmp_path, routes=routes)
    r = store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "failed" and r.error == "too_large"
    assert led.spent == 0


@pytest.mark.parametrize("written,charged", [(0, 0), (5, len(BODY))])
def test_internal_error_settles_and_records(tmp_path, written, charged):
    t, f, store, led = _setup(tmp_path)

    def boom(url, dest, max_bytes, hashers):
        dest.write_bytes(b"x" * written)
        raise RuntimeError("bug")

    f.download = boom
    r = store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert r.status == "failed" and r.error == "internal_RuntimeError"
    assert led.spent == charged and led.open == {}
    assert list(store.tmp.iterdir()) == []


@pytest.mark.parametrize("code", ["ENOSPC", "EDQUOT"])
def test_disk_full_is_fatal(tmp_path, code):
    import errno

    from sherlock.collect.store import DiskError

    t, f, store, led = _setup(tmp_path)

    def full(url, dest, max_bytes, hashers):
        dest.write_bytes(b"x" * 7)
        raise OSError(getattr(errno, code), "No space left on /some/abs/path")

    f.download = full
    with pytest.raises(DiskError):
        store.fetch_item(f, led, _item(), "nuget-20261125-aaaaaaaaaaaa")
    assert led.open == {} and list(store.tmp.iterdir()) == []

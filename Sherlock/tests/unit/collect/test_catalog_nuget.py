"""The NuGet planner against a synthetic catalogue (offline)."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace

import pytest

from sherlock.collect.catalog import nuget
from sherlock.collect.http import HostTripped


def test_plans_sorted_with_sha512_hex_and_urls(nuget_fake, fake_getter):
    cat, pay = nuget_fake()
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    assert res.source == "nuget"
    ids = [i.meta["package"] for i in res.items]
    assert ids == ["alpha.tools", "mid.pkg", "zeta.lib"]  # C15: local sort
    for it in res.items:
        assert it.url in pay
        assert it.expected["sha512"] == hashlib.sha512(pay[it.url]).hexdigest()
        assert it.size == len(pay[it.url])
    # +build metadata stripped before URLs and keys
    assert res.items[0].key == "nuget:alpha.tools/1.2.3"


def test_nuget_base64_sha512_verified(nuget_fake, fake_getter):
    cat, pay = nuget_fake()
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    it = res.items[0]
    b64 = base64.b64encode(hashlib.sha512(pay[it.url]).digest()).decode()
    assert base64.b64decode(b64).hex() == it.expected["sha512"]
    assert set(it.expected) == {"sha512"}


def test_nuget_created_not_published(nuget_fake, fake_getter):
    cat, _ = nuget_fake()
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    m = res.items[0].meta
    assert m["date_kind"] == "nuget_created"
    assert m["source_date"] == "2024-03-05"
    assert "1900" not in json.dumps(m)


def test_meta_owner_microsoft_and_vendor_evidence(nuget_fake, fake_getter):
    cat, _ = nuget_fake()
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    by = {i.meta["package"]: i.meta for i in res.items}
    assert by["zeta.lib"]["owner_microsoft"] is True
    assert by["alpha.tools"]["owner_microsoft"] is False
    assert by["alpha.tools"]["vendor_evidence"]["owners"] == ["someone"]
    assert by["mid.pkg"]["vendor_evidence"]["verified"] is True
    assert by["zeta.lib"]["licence"] == {"expression": "MIT", "url": None}
    assert by["zeta.lib"]["catalog_url"].startswith(
        "https://api.nuget.org/v3/catalog0/"
    )


def test_anchors_hold_index_and_search_pages(nuget_fake, fake_getter):
    cat, _ = nuget_fake()
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    assert len(res.anchors) == 5
    assert res.anchors["index.json"] == cat["https://api.nuget.org/v3/index.json"]


def test_plain_registration_and_object_catalog_entry(nuget_fake, fake_getter):
    pk = [{"id": "One", "version": "1.0.0", "owners": [], "entry_object": True}]
    cat, _ = nuget_fake(pk, gzip_reg=False)
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    assert len(res.items) == 1


def test_per_package_failures_are_drops(nuget_fake, fake_getter):
    pk = [
        {"id": "Good", "version": "1.0.0"},
        {"id": "BadAlg", "version": "1.0.0", "alg": "SHA256"},
        {"id": "Gone", "version": "1.0.0"},
    ]
    cat, _ = nuget_fake(pk)
    cat = {k: v for k, v in cat.items() if "/gone/" not in k}
    res = nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)
    assert [i.meta["package"] for i in res.items] == ["good"]
    assert res.dropped == {"hash_alg_not_sha512": 1, "registration_not_found": 1}


def test_max_packages_limits_after_sort(nuget_fake, fake_getter):
    cat, _ = nuget_fake()
    get = fake_getter(cat)
    res = nuget.plan(get, replace(nuget.DEFAULT_CONFIG, max_packages=1))
    assert [i.meta["package"] for i in res.items] == ["alpha.tools"]
    assert res.stats["n_selected"] == 1


def test_search_paging_respects_skip_limit(nuget_fake, fake_getter):
    cat, _ = nuget_fake()
    get = fake_getter(cat)
    nuget.plan(get, nuget.DEFAULT_CONFIG)
    searches = [u for u in get.calls if "skip=" in u]
    assert len(searches) == 4 and all("prerelease=false" in u for u in searches)
    with pytest.raises(ValueError):
        nuget.NugetConfig(n_search=5000)


def test_tripped_host_is_fatal_not_a_drop(nuget_fake, fake_getter):
    cat, _ = nuget_fake()
    inner = fake_getter(cat)

    def get(url, n):
        if "/catalog0/" in url:
            raise HostTripped("tripped")
        return inner(url, n)

    with pytest.raises(HostTripped):
        nuget.plan(get, nuget.DEFAULT_CONFIG)


def test_empty_search_is_an_error(nuget_fake, fake_getter):
    cat, _ = nuget_fake([])
    with pytest.raises(ValueError, match="no packages"):
        nuget.plan(fake_getter(cat), nuget.DEFAULT_CONFIG)


def test_search_page_too_large_is_a_clear_plan_failure(nuget_fake, fake_getter):
    from sherlock.collect.http import TooLarge

    assert nuget.DEFAULT_CONFIG.max_search_bytes == 64 << 20
    cat, _ = nuget_fake()
    inner = fake_getter(cat)

    def get(url, n):
        if "skip=" in url:
            raise TooLarge("over")
        return inner(url, n)

    with pytest.raises(ValueError, match="max_search_bytes"):
        nuget.plan(get, nuget.DEFAULT_CONFIG)

"""The plan-item contract shared by every catalogue planner."""

from __future__ import annotations

import pytest

from sherlock.collect.items import CatalogResult, PlanItem


def _item(**kw):
    base = dict(
        source="nuget",
        key="nuget:example.lib/1.0.0",
        url="https://api.example.test/example.lib.1.0.0.nupkg",
        expected={"sha512": "ab" * 64},
        size=123,
        meta={"package": "example.lib", "version": "1.0.0"},
    )
    base.update(kw)
    return PlanItem(**base)


def test_round_trip():
    it = _item()
    assert PlanItem.from_dict(it.to_dict()) == it


def test_md5_sha1_never_suffice():
    with pytest.raises(ValueError):
        _item(expected={"md5": "ab" * 16})
    with pytest.raises(ValueError):
        _item(expected={"sha1": "ab" * 20})
    with pytest.raises(ValueError):
        _item(expected={})


def test_digest_must_be_lowercase_hex_of_right_length():
    with pytest.raises(ValueError):
        _item(expected={"sha256": "AB" * 32})
    with pytest.raises(ValueError):
        _item(expected={"sha256": "ab" * 31})


def test_https_only():
    with pytest.raises(ValueError):
        _item(url="http://api.example.test/x.nupkg")


def test_size_non_negative():
    with pytest.raises(ValueError):
        _item(size=-1)


def test_catalog_result_rejects_duplicate_keys():
    a = _item()
    with pytest.raises(ValueError):
        CatalogResult(source="nuget", items=(a, a))

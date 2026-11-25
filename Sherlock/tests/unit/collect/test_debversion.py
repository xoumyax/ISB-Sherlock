"""dpkg version ordering (deb-version(7)): epoch, upstream, revision, the ~ rule."""

from __future__ import annotations

import pytest

from sherlock.collect.catalog.debversion import compare, parse, sort_key

LESS = [
    ("1.0~rc1", "1.0"),
    ("2.0", "1:0.1"),
    ("1.0-1", "1.0-1ubuntu1"),
    ("8.0.11-0ubuntu1~24.04.1", "8.0.11-0ubuntu1"),
    ("1.0~~", "1.0~"),
    ("1.0~", "1.0"),
    ("1.0", "1.0a"),
    ("1.0a", "1.0+"),  # letters sort before non-letters
    ("1.0+", "1.0.1"),
    ("2.0", "10.0"),
    ("1.2.3", "1.2.10"),
    ("0.9-9", "1.0-1"),
    ("1.0-1", "1.0-2"),
    ("1.0-9", "1.0-10"),
    ("8.0.110-0ubuntu1~24.04.1", "8.0.111-0ubuntu1~24.04.1"),
    ("1:1.0", "2:0.1"),
    ("9.0", "1:0"),
]

EQUAL = [
    ("1.0", "1.00"),
    ("1.0", "0:1.0"),
    ("1.0-0", "1.0-00"),
    ("1.01", "1.1"),
]


@pytest.mark.parametrize(("a", "b"), LESS)
def test_known_pairs_order(a, b):
    assert compare(a, b) < 0
    assert compare(b, a) > 0


@pytest.mark.parametrize(("a", "b"), EQUAL)
def test_equal_pairs(a, b):
    assert compare(a, b) == 0


def test_upstream_may_contain_hyphen_and_colon():
    # revision is after the LAST hyphen; epoch before the FIRST colon
    assert parse("1:2.0-rc-3") == (1, "2.0-rc", "3")
    assert parse("1:2:3-4") == (1, "2:3", "4")
    assert parse("1.0") == (0, "1.0", "")


def test_sort_key_sorts():
    vs = ["1.0", "1.0~rc1", "1:0.1", "1.0-1ubuntu1", "1.0-1"]
    assert sorted(vs, key=sort_key) == [
        "1.0~rc1",
        "1.0",
        "1.0-1",
        "1.0-1ubuntu1",
        "1:0.1",
    ]


@pytest.mark.parametrize("bad", ["", "a:1.0", "1.0 2", "-1", "1:", ":1.0"])
def test_invalid_versions_raise(bad):
    with pytest.raises(ValueError):
        parse(bad)

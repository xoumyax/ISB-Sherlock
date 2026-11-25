"""Shared offline fixtures for collect tests: a tiny synthetic NuGet catalogue."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest

from sherlock.collect.http import HttpStatusError

API = "https://api.nuget.org"
SEARCH = "https://api.nuget.org/query"  # real index points elsewhere; see report
REG = f"{API}/v3/registration5-gz-semver2/"
FLAT = f"{API}/v3-flatcontainer/"


def build_nuget(
    packages: list[dict[str, Any]] | None = None, *, gzip_reg: bool = True
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """(catalogue url -> bytes, payload url -> bytes) for a fake nuget.org."""
    if packages is None:
        packages = [
            {"id": "Zeta.Lib", "version": "2.0.0", "owners": ["Microsoft", "dotnet"]},
            {"id": "alpha.tools", "version": "1.2.3+build.5", "owners": "someone"},
            {"id": "Mid.Pkg", "version": "0.9.0", "owners": ["x"], "verified": True},
        ]
    cat: dict[str, bytes] = {}
    pay: dict[str, bytes] = {}
    index = {
        "version": "3.0.0",
        "resources": [
            {"@id": SEARCH, "@type": "SearchQueryService"},
            {"@id": REG, "@type": "RegistrationsBaseUrl/3.6.0"},
            {"@id": f"{API}/v3/registration5/", "@type": "RegistrationsBaseUrl"},
            {"@id": FLAT, "@type": "PackageBaseAddress/3.0.0"},
        ],
    }
    cat[f"{API}/v3/index.json"] = json.dumps(index).encode()
    data = [
        {
            "id": p["id"],
            "version": p["version"],
            "owners": p.get("owners", []),
            "authors": p.get("authors", ["A. Author"]),
            "verified": p.get("verified", False),
        }
        for p in packages
    ]
    for skip in (0, 1000, 2000, 3000):
        page = data if skip == 0 else []
        url = f"{SEARCH}?q=&skip={skip}&take=1000&prerelease=false&semVerLevel=2.0.0"
        cat[url] = json.dumps({"totalHits": len(data), "data": page}).encode()
    for p in packages:
        idl = p["id"].lower()
        verl = p["version"].lower().split("+")[0]
        body = p.get("body") or f"PK synthetic {idl} {verl}".encode() * 20
        leaf_url = f"{API}/v3/catalog0/data/2026.01.01/{idl}.{verl}.json"
        reg_leaf = {"@id": f"{REG}{idl}/{verl}.json", "catalogEntry": leaf_url}
        if p.get("entry_object"):
            reg_leaf["catalogEntry"] = {"@id": leaf_url}
        rb = json.dumps(reg_leaf).encode()
        cat[f"{REG}{idl}/{verl}.json"] = gzip.compress(rb) if gzip_reg else rb
        leaf = {
            "id": p["id"],
            "version": verl,
            "packageHash": base64.b64encode(hashlib.sha512(body).digest()).decode(),
            "packageHashAlgorithm": p.get("alg", "SHA512"),
            "packageSize": len(body),
            "created": "2024-03-05T10:11:12.123+00:00",
            "published": "1900-01-01T00:00:00+00:00",
            "authors": "A. Author",
            "licenseExpression": "MIT",
            "projectUrl": "https://example.test/project",
        }
        cat[leaf_url] = json.dumps(leaf).encode()
        pay[f"{FLAT}{idl}/{verl}/{idl}.{verl}.nupkg"] = body
    return cat, pay


def make_getter(cat: dict[str, bytes]) -> Callable[[str, int], bytes]:
    calls: list[str] = []

    def get(url: str, max_bytes: int) -> bytes:
        calls.append(url)
        if url not in cat:
            raise HttpStatusError(404, url)
        body = cat[url]
        if len(body) > max_bytes:
            raise ValueError("oversize")
        return body

    get.calls = calls  # type: ignore[attr-defined]
    return get


@pytest.fixture
def nuget_fake():
    return build_nuget


@pytest.fixture
def fake_getter():
    return make_getter

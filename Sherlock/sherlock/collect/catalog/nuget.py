"""NuGet planner: the first 4,000 packages of an empty search, sorted locally (C15).

Chain (COLLECT §2, §3.4): service index -> search pages (anchors) -> registration
leaf -> catalog leaf, whose ``packageHash`` (SHA512, base64) and ``packageSize``
anchor the ``.nupkg`` from the flat container. Only SHA512 is accepted
(``packageHashAlgorithm`` must say so); the hash is turned into lowercase hex.

Facts this module relies on (Appendix C, 24 Nov 2026): V3 search has no sort, so
the selection is "first N of an empty query", then sorted by lowercase id here;
``skip`` is at most 3,000 and ``take`` at most 1,000. The date is the catalog
leaf's ``created``, never ``published`` (``published`` reads 1900 for unlisted
packages; H6). Microsoft ownership is by the search result's listed owners (C15).

Registration hives: ``RegistrationsBaseUrl/3.6.0`` (gzip, includes SemVer 2.0.0
packages) is preferred, plain ``RegistrationsBaseUrl`` is the fallback. Bodies
starting with the gzip magic are decompressed with a byte bound, so either works.

Per-package failures (404, bad JSON, wrong hash algorithm) become
``dropped[reason]``. Network failures that mean the host is gone (a tripped
breaker, TLS, a refused redirect or off-allowlist host) are raised: they would
otherwise yield a near-empty plan that "succeeds".
"""

from __future__ import annotations

import base64
import binascii
import json
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sherlock.collect.http import (
    HostTripped,
    HttpStatusError,
    RedirectRefused,
    TlsError,
    TooLarge,
)
from sherlock.collect.items import CatalogResult, Getter, PlanItem

__all__ = ["DEFAULT_CONFIG", "SOURCE", "NugetConfig", "plan"]

SOURCE = "nuget"

_FATAL = (HostTripped, TlsError, RedirectRefused)


@dataclass(frozen=True)
class NugetConfig:
    service_index_url: str = "https://api.nuget.org/v3/index.json"
    #: How many search results to read (C15: first 4,000 of an empty query).
    n_search: int = 4000
    #: Search page size (the API's take limit is 1,000).
    page: int = 1000
    #: Packages planned after the local sort; None = all (smoke runs set it).
    max_packages: int | None = None
    prerelease: bool = False
    #: Read bounds per document (bytes), raw and decompressed.
    max_index_bytes: int = 1 << 20
    max_search_bytes: int = 64 << 20
    max_leaf_bytes: int = 4 << 20

    def __post_init__(self) -> None:
        if self.page <= 0 or self.page > 1000:
            raise ValueError("page must be in 1..1000 (NuGet take limit)")
        if self.n_search <= 0 or self.n_search - self.page > 3000:
            raise ValueError("n_search must keep skip <= 3000 (NuGet search limit)")
        if self.max_packages is not None and self.max_packages < 0:
            raise ValueError("max_packages must be None or >= 0")


DEFAULT_CONFIG = NugetConfig()


# -- helpers ------------------------------------------------------------------


def _bump(d: dict[str, int], reason: str, n: int = 1) -> None:
    d[reason] = d.get(reason, 0) + n


def _maybe_gunzip(body: bytes, limit: int) -> bytes:
    if body[:2] != b"\x1f\x8b":
        return body
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(body, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError("decompressed document over its bound")
    return out


def _json(get: Getter, url: str, limit: int) -> Any:
    return json.loads(_maybe_gunzip(get(url, limit), limit))


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return [str(s) for s in v if s]


def _resource(index: Mapping[str, Any], *types: str) -> str:
    resources = index.get("resources") or []
    for want in types:
        for r in resources:
            t = r.get("@type")
            ts = t if isinstance(t, list) else [t]
            if want in ts and r.get("@id"):
                url = str(r["@id"])
                return url if url.endswith("/") or "Search" in want else url + "/"
    raise ValueError(f"service index has no {types[0]} resource")


def _norm_version(v: str) -> str:
    return v.split("+", 1)[0].strip().lower()


# -- planner ------------------------------------------------------------------


def plan(get: Getter, config: NugetConfig = DEFAULT_CONFIG) -> CatalogResult:
    anchors: dict[str, bytes] = {}
    dropped: dict[str, int] = {}

    raw_index = get(config.service_index_url, config.max_index_bytes)
    anchors["index.json"] = raw_index
    index = json.loads(_maybe_gunzip(raw_index, config.max_index_bytes))
    search = _resource(
        index,
        "SearchQueryService",
        "SearchQueryService/3.5.0",
        "SearchQueryService/3.0.0-rc",
    )
    reg = _resource(index, "RegistrationsBaseUrl/3.6.0", "RegistrationsBaseUrl")
    flat = _resource(index, "PackageBaseAddress/3.0.0")

    # Search pages: id -> first search result seen.
    found: dict[str, Mapping[str, Any]] = {}
    n_results = 0
    pre = "true" if config.prerelease else "false"
    for skip in range(0, config.n_search, config.page):
        take = min(config.page, config.n_search - skip)
        url = f"{search}?q=&skip={skip}&take={take}&prerelease={pre}&semVerLevel=2.0.0"
        try:
            body = get(url, config.max_search_bytes)
        except TooLarge:
            raise ValueError(
                f"NuGet search page skip={skip} is over {config.max_search_bytes} "
                "bytes; raise NugetConfig.max_search_bytes"
            ) from None
        anchors[f"search-skip{skip:04d}.json"] = body
        page = json.loads(_maybe_gunzip(body, config.max_search_bytes))
        for row in page.get("data") or []:
            n_results += 1
            pid = str(row.get("id") or "").strip()
            if not pid or not row.get("version"):
                _bump(dropped, "search_row_incomplete")
                continue
            found.setdefault(pid.lower(), row)
    n_unique = len(found)
    if not found:
        raise ValueError("NuGet search returned no packages; refusing an empty plan")
    selected = sorted(found)
    if config.max_packages is not None:
        if len(selected) > config.max_packages:
            _bump(dropped, "max_packages", len(selected) - config.max_packages)
        selected = selected[: config.max_packages]

    items: list[PlanItem] = []
    for idl in selected:
        row = found[idl]
        try:
            item = _plan_one(get, config, row, idl, reg, flat, dropped)
        except _FATAL:
            raise
        except HttpStatusError as exc:
            _bump(
                dropped,
                "registration_not_found"
                if exc.status == 404
                else f"catalog_{exc.reason}",
            )
            continue
        except (ValueError, KeyError, TypeError, AttributeError):
            _bump(dropped, "catalog_parse_error")
            continue
        except Exception:  # noqa: BLE001 - unknown upstream failure, recorded
            _bump(dropped, "catalog_fetch_failed")
            continue
        if item is not None:
            items.append(item)

    return CatalogResult(
        source=SOURCE,
        items=tuple(items),
        anchors=anchors,
        dropped=dropped,
        stats={
            "n_search_results": n_results,
            "n_unique_ids": n_unique,
            "n_selected": len(selected),
            "registration_hive": reg.rstrip("/").rsplit("/", 1)[-1],
        },
    )


def _plan_one(
    get: Getter,
    config: NugetConfig,
    row: Mapping[str, Any],
    idl: str,
    reg: str,
    flat: str,
    dropped: dict[str, int],
) -> PlanItem | None:
    verl = _norm_version(str(row["version"]))
    leaf = _json(get, f"{reg}{idl}/{verl}.json", config.max_leaf_bytes)
    entry = leaf.get("catalogEntry")
    catalog_url = entry.get("@id") if isinstance(entry, Mapping) else entry
    if not isinstance(catalog_url, str) or not catalog_url.startswith("https://"):
        _bump(dropped, "no_catalog_entry")
        return None
    cl = _json(get, catalog_url, config.max_leaf_bytes)
    if str(cl.get("packageHashAlgorithm", "")).upper() != "SHA512":
        _bump(dropped, "hash_alg_not_sha512")
        return None
    try:
        digest = base64.b64decode(str(cl["packageHash"]), validate=True)
    except (binascii.Error, KeyError):
        _bump(dropped, "bad_package_hash")
        return None
    if len(digest) != 64:
        _bump(dropped, "bad_package_hash")
        return None
    size = cl.get("packageSize")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        _bump(dropped, "bad_package_size")
        return None
    created = cl.get("created")
    source_date = str(created)[:10] if isinstance(created, str) and created else None
    if source_date is not None and source_date.startswith("1900"):
        source_date = None
    owners = _as_list(row.get("owners"))
    authors = _as_list(cl.get("authors")) or _as_list(row.get("authors"))
    return PlanItem(
        source=SOURCE,
        key=f"nuget:{idl}/{verl}",
        url=f"{flat}{idl}/{verl}/{idl}.{verl}.nupkg",
        expected={"sha512": digest.hex()},
        size=size,
        meta={
            "package": idl,
            "package_id": str(row.get("id")),
            "version": verl,
            "catalog_url": catalog_url,
            "source_date": source_date,
            "source_time": created if isinstance(created, str) else None,
            "date_kind": "nuget_created",
            "vendor_evidence": {
                "owners": owners,
                "authors": authors,
                "verified": bool(row.get("verified", False)),
            },
            "owner_microsoft": any(o.lower() == "microsoft" for o in owners),
            "licence": {
                "expression": cl.get("licenseExpression") or None,
                "url": cl.get("licenseUrl") or None,
            },
            "project_url": cl.get("projectUrl") or None,
        },
    )

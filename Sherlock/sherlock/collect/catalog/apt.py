"""apt planner (W6): Debian/Ubuntu InRelease -> Packages SHA256/SHA512 -> .deb rows.

Linux archives ship Windows bytes: Mono's ``libmono-*-cil`` assemblies, Wine's PE
DLLs, the .NET runtime/SDK, and Microsoft-signed EFI binaries (shim, grub, fwupd).
This module plans which ``.deb`` files to fetch; it never unpacks one.

Chain (COLLECT.md §3, Appendix C; DECISIONS C14, C19): ``dists/<suite>/InRelease``
(bounded) is a clearsigned Release file. There are no keyrings on the node (C19), so
the signature is NOT verified here: each item is marked ``release_sig:
"unverified"``, carries the InRelease sha256, and the exact InRelease bytes are kept
as an anchor so an offline gpgv can check the chain before anything is promoted.
The Release's SHA256 (or SHA512) list anchors each ``Packages`` index; the index is
size- and digest-checked before it is decompressed (with an output bound) and parsed,
and each stanza's SHA256/SHA512 anchors its ``.deb``. MD5 and SHA-1 never count.

Failure modes handled with a ``dropped[reason]`` count instead of a crash: a repo
whose InRelease is missing or malformed (``repo_failed:<name>/<suite>``), an index
not listed with a strong digest, an index digest mismatch, a decompression bomb, a
stanza with a traversal ``Filename`` or no strong digest. Versions are ordered by
dpkg rules (``debversion``); only the newest ``versions_per_package`` per (repo,
package) are kept. ``pmc.py`` reuses this machinery for packages.microsoft.com.
"""

from __future__ import annotations

import hashlib
import lzma
import re
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any

from sherlock.collect.catalog.debversion import parse as parse_version
from sherlock.collect.catalog.debversion import sort_key
from sherlock.collect.items import CatalogResult, Getter, PlanItem

__all__ = [
    "DEFAULT_CONFIG",
    "SOURCE",
    "AptConfig",
    "RepoSpec",
    "bounded_decompress",
    "parse_clearsigned",
    "parse_packages",
    "parse_release",
    "plan",
    "plan_repos",
]

SOURCE = "apt"

_MiB = 1 << 20
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
#: Debug/doc packages, also mid-name (Ubuntu's ``dotnet-runtime-dbg-8.0``).
_DBG_DOC = r".*-(dbg|dbgsym|doc)(-.*)?"


# -- config --


@dataclass(frozen=True)
class RepoSpec:
    """One ``{base_url}/dists/{suite}`` with the components and packages wanted."""

    #: Short label used in item keys, anchors and drop reasons (e.g. ``ubuntu``).
    #: Suites sharing a name are one repo for newest-version selection.
    name: str
    #: Archive root holding ``dists/`` and ``pool/``; must be https.
    base_url: str
    #: Suite or codename, e.g. ``trixie``, ``noble-updates``.
    suite: str
    #: Components whose ``binary-{arch}/Packages`` index is read.
    components: tuple[str, ...]
    #: Architecture index to read; ``Architecture: all`` stanzas in it are kept too.
    arch: str = "amd64"
    #: Regexes (full match on ``Package``); a package is wanted if any matches.
    select: tuple[str, ...] = ()
    #: Regexes (full match) that veto a selected package (debug symbols, docs).
    exclude: tuple[str, ...] = (_DBG_DOC,)

    def __post_init__(self) -> None:
        if not _NAME.match(self.name):
            raise ValueError(f"RepoSpec.name {self.name!r}: use [A-Za-z0-9._+-]")
        if not self.base_url.startswith("https://") or self.base_url.endswith("/"):
            raise ValueError(
                f"RepoSpec.base_url {self.base_url!r}: https, no trailing slash"
            )
        for label, v in [("suite", self.suite), ("arch", self.arch)]:
            if not _NAME.match(v) or ".." in v:
                raise ValueError(f"RepoSpec.{label} {v!r}: use [A-Za-z0-9._+-]")
        comps = tuple(self.components)
        if not comps or any(not _NAME.match(c) or ".." in c for c in comps):
            raise ValueError(f"RepoSpec.components {comps!r}: plain names, at least 1")
        object.__setattr__(self, "components", comps)
        object.__setattr__(self, "select", tuple(self.select))
        object.__setattr__(self, "exclude", tuple(self.exclude))
        if not self.select:
            raise ValueError(f"RepoSpec {self.name}: select needs at least one regex")
        for rx in self.select + self.exclude:
            try:
                re.compile(rx)
            except re.error as e:
                raise ValueError(f"RepoSpec {self.name}: bad regex {rx!r}: {e}") from e

    @property
    def label(self) -> str:
        return f"{self.name}/{self.suite}"

    def selects(self, package: str) -> bool:
        """True if ``package`` matches a select regex and no exclude regex."""
        if not any(re.fullmatch(rx, package) for rx in self.select):
            return False
        return not any(re.fullmatch(rx, package) for rx in self.exclude)


@dataclass(frozen=True)
class AptConfig:
    """Repos to read and the bounds on untrusted catalogue bytes."""

    #: Repos in priority order: on a duplicate the earlier repo/suite is kept.
    repos: tuple[RepoSpec, ...] = ()
    #: Newest N dpkg versions kept per (repo name, package). PMC lists hundreds.
    versions_per_package: int = 1
    #: Smoke-run cap on selected packages, round-robin over (repo, suite) groups in
    #: sorted order, by package name within a group. None = all.
    max_packages: int | None = None
    #: InRelease is ~100-300 KiB on Debian/Ubuntu; refuse anything far larger.
    max_inrelease_bytes: int = 8 * _MiB
    #: Compressed Packages index bound (Ubuntu universe Packages.xz is ~20 MiB).
    max_index_bytes: int = 64 * _MiB
    #: Decompressed Packages bound; refuses xz/gzip bombs.
    max_index_decompressed_bytes: int = 512 * _MiB

    def __post_init__(self) -> None:
        object.__setattr__(self, "repos", tuple(self.repos))
        if self.versions_per_package < 1:
            raise ValueError("versions_per_package must be >= 1")
        if self.max_packages is not None and self.max_packages < 0:
            raise ValueError("max_packages must be None or >= 0")
        for k in (
            "max_inrelease_bytes",
            "max_index_bytes",
            "max_index_decompressed_bytes",
        ):
            if getattr(self, k) <= 0:
                raise ValueError(f"{k} must be > 0")
        labels = [r.label for r in self.repos]
        if len(labels) != len(set(labels)):
            raise ValueError("duplicate repo name/suite in AptConfig.repos")


_DEBIAN_SELECT = (
    r"mono-runtime.*",
    r"mono-.*",
    r"libmono-.*-cil",
    r"wine.*",
    r"libwine.*",
    r"shim-signed.*",
    r"grub-efi-amd64-signed",
    r"fwupd-amd64-signed",
    r"fwupd-efi.*",
)
_UBUNTU_SELECT = (
    r"dotnet.*",
    r"aspnetcore.*",
    r"netstandard-targeting-pack.*",
    r"mono-.*",
    r"libmono-.*-cil",
    r"wine.*",
    r"libwine.*",
    r"shim-signed",
    r"grub-efi-amd64-signed",
    r"fwupd-signed.*",
)
#: ``dotnet-sdk-*-source-built-artifacts`` is a very large tarball of build
#: outputs (budget, C13); excluded by default, revisit after the smoke run.
_EXCLUDE = (_DBG_DOC, r"linux-.*", r".*-source-built-artifacts")

_DEBIAN = "https://deb.debian.org/debian"
_UBUNTU = "https://archive.ubuntu.com/ubuntu"

#: Suite names are unverified offline; the smoke run confirms them.
DEFAULT_CONFIG = AptConfig(
    repos=(
        RepoSpec(
            "debian",
            _DEBIAN,
            "trixie",
            ("main", "contrib"),
            select=_DEBIAN_SELECT,
            exclude=_EXCLUDE,
        ),
        RepoSpec(
            "ubuntu",
            _UBUNTU,
            "noble",
            ("main", "universe"),
            select=_UBUNTU_SELECT,
            exclude=_EXCLUDE,
        ),
        RepoSpec(
            "ubuntu",
            _UBUNTU,
            "noble-updates",
            ("main", "universe"),
            select=_UBUNTU_SELECT,
            exclude=_EXCLUDE,
        ),
    )
)


# -- parsing --

_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----"
_SIG = "-----BEGIN PGP SIGNATURE-----"
_END = "-----END PGP SIGNATURE-----"


def parse_clearsigned(raw: bytes) -> str:
    """Return the signed body of a clearsigned message (dash-escaping undone).

    The signature is not verified (C19). Raises ValueError if the framing is wrong.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("InRelease is not UTF-8") from e
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].rstrip() != _BEGIN:
        raise ValueError("not a clearsigned message")
    i += 1
    while i < len(lines) and lines[i].strip():  # armor headers (Hash: ...)
        if ":" not in lines[i]:
            raise ValueError("bad armor header")
        i += 1
    if i >= len(lines):
        raise ValueError("clearsigned message has no body")
    i += 1
    body: list[str] = []
    while i < len(lines) and lines[i].rstrip() != _SIG:
        ln = lines[i]
        if ln.startswith("- "):
            ln = ln[2:]
        elif ln.startswith("-"):
            raise ValueError("unescaped dash line in clearsigned body")
        body.append(ln)
        i += 1
    if i >= len(lines) or not any(ln.rstrip() == _END for ln in lines[i:]):
        raise ValueError("clearsigned message has no signature block")
    return "\n".join(body).rstrip("\n") + "\n"


def _deb822(text: str) -> list[dict[str, str]]:
    stanzas: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    last: str | None = None
    for ln in text.split("\n"):
        if not ln.strip():
            if cur:
                stanzas.append(cur)
            cur, last = {}, None
            continue
        if ln[0] in " \t":
            if last is not None:
                cur[last] += "\n" + ln[1:]
            continue
        if ln.startswith("#") or ":" not in ln:
            last = None
            continue
        k, v = ln.split(":", 1)
        last = k.strip()
        cur[last] = v.strip()
    if cur:
        stanzas.append(cur)
    return stanzas


def parse_packages(text: str) -> list[dict[str, str]]:
    """Parse a deb822 Packages file into stanzas (continuation lines joined)."""
    return _deb822(text)


_HASH_FIELDS = {"SHA256": "sha256", "SHA512": "sha512"}
_WEAK_FIELDS = ("MD5Sum", "MD5sum", "SHA1")


def _iso_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError, IndexError):
        return None


def parse_release(body: str) -> dict[str, Any]:
    """Fields of a Release body; ``files`` maps path -> (size, {alg: hex})."""
    st = _deb822(body)
    if not st:
        raise ValueError("empty Release")
    f = st[0]
    files: dict[str, tuple[int, dict[str, str]]] = {}
    weak: set[str] = set()
    for fld, alg in _HASH_FIELDS.items():
        for ln in f.get(fld, "").split("\n"):
            parts = ln.split()
            if len(parts) != 3 or not parts[1].isdigit():
                continue
            hexd, size, path = parts[0].lower(), int(parts[1]), parts[2]
            prev = files.get(path)
            if prev is not None and prev[0] != size:
                raise ValueError(f"Release lists {path} with two sizes")
            files.setdefault(path, (size, {}))[1][alg] = hexd
    for fld in _WEAK_FIELDS:
        for ln in f.get(fld, "").split("\n"):
            parts = ln.split()
            if len(parts) == 3:
                weak.add(parts[2])
    return {
        "date": _iso_date(f.get("Date")),
        "valid_until": _iso_date(f.get("Valid-Until")),
        "architectures": f.get("Architectures", "").split(),
        "components": f.get("Components", "").split(),
        "files": files,
        "weak_only": weak - set(files),
    }


def bounded_decompress(data: bytes, kind: str, max_out: int) -> bytes:
    """Decompress ``xz``/``gz``/``plain`` with an output bound; ValueError past it."""
    if kind == "plain":
        if len(data) > max_out:
            raise ValueError("index exceeds decompressed bound")
        return data
    chunk = _MiB
    out = bytearray()
    if kind == "xz":
        xd = lzma.LZMADecompressor()
        buf = data
        while True:
            try:
                piece = xd.decompress(buf, max_length=chunk)
            except lzma.LZMAError as e:
                raise ValueError(f"bad xz stream: {e}") from e
            buf = b""
            out += piece
            if len(out) > max_out:
                raise ValueError("index exceeds decompressed bound")
            if xd.eof:
                if xd.unused_data:
                    raise ValueError("trailing data after xz stream")
                return bytes(out)
            if xd.needs_input:
                raise ValueError("truncated xz stream")
    if kind == "gz":
        zd = zlib.decompressobj(16 + zlib.MAX_WBITS)
        buf = data
        while True:
            try:
                piece = zd.decompress(buf, chunk)
            except zlib.error as e:
                raise ValueError(f"bad gzip stream: {e}") from e
            buf = zd.unconsumed_tail
            out += piece
            if len(out) > max_out:
                raise ValueError("index exceeds decompressed bound")
            if zd.eof:
                if zd.unused_data:
                    raise ValueError("trailing data after gzip stream")
                return bytes(out)
            if not buf and not piece:
                raise ValueError("truncated gzip stream")
    raise ValueError(f"unknown compression {kind!r}")


# -- planning --


@dataclass
class _Cand:
    order: int  # repo position in config, for "earlier wins"
    spec: RepoSpec
    component: str
    catalog_url: str
    release: Mapping[str, Any]
    inrelease_sha256: str
    st: Mapping[str, str]
    expected: dict[str, str] = field(default_factory=dict)


def _bump(d: dict[str, int], k: str, n: int = 1) -> None:
    d[k] = d.get(k, 0) + n


_HEX = re.compile(r"^[0-9a-f]+$")


def _safe_filename(fn: str) -> bool:
    if not fn or fn.startswith("/") or "\\" in fn or "\x00" in fn:
        return False
    if ":" in fn or "?" in fn or "#" in fn or "%" in fn:
        return False
    parts = fn.split("/")
    return all(p not in ("", ".", "..") for p in parts)


def _read_repo(
    get: Getter,
    spec: RepoSpec,
    order: int,
    cfg: AptConfig,
    source: str,
    anchors: dict[str, bytes],
    dropped: dict[str, int],
    stats: dict[str, Any],
) -> list[_Cand]:
    rs: dict[str, Any] = {"stanzas": 0, "selected": 0, "indexes": []}
    stats["per_repo"][spec.label] = rs
    dists = f"{spec.base_url}/dists/{spec.suite}"
    try:
        raw = get(f"{dists}/InRelease", cfg.max_inrelease_bytes)
        rel = parse_release(parse_clearsigned(raw))
    except Exception as e:  # noqa: BLE001 - one repo failing must not stop others
        _bump(dropped, f"repo_failed:{spec.label}")
        rs["error"] = type(e).__name__
        return []
    inrel_sha = hashlib.sha256(raw).hexdigest()
    anchors[f"{source}/{spec.label}/InRelease"] = raw
    rs.update(
        release_date=rel["date"],
        valid_until=rel["valid_until"],
        inrelease_sha256=inrel_sha,
        release_sig="unverified",
    )
    # gate only when the field is present; a missing index is caught per component
    if rel["architectures"] and spec.arch not in rel["architectures"]:
        _bump(dropped, "arch_not_in_release")
        return []
    out: list[_Cand] = []
    for comp in spec.components:
        base = f"{comp}/binary-{spec.arch}/Packages"
        names = [(base + ".xz", "xz"), (base + ".gz", "gz"), (base, "plain")]
        listed = [(p, k) for p, k in names if p in rel["files"]]
        if not listed:
            weak = any(p in rel["weak_only"] for p, _k in names)
            _bump(dropped, "index_weak_digest_only" if weak else "index_not_in_release")
            continue
        data = None
        too_large = False
        for path, kind in listed:
            size, digests = rel["files"][path]
            if size > cfg.max_index_bytes:
                too_large = True
                continue
            try:
                body = get(f"{dists}/{path}", cfg.max_index_bytes)
            except Exception:  # noqa: BLE001 - try the next listed compression
                continue
            data = (path, kind, body, size, digests)
            break
        if data is None:
            _bump(dropped, "index_too_large" if too_large else "index_fetch_failed")
            continue
        path, kind, body, size, digests = data
        if len(body) != size or any(
            hashlib.new(alg, body).hexdigest() != hexd for alg, hexd in digests.items()
        ):
            _bump(dropped, "index_digest_mismatch")
            continue
        try:
            text = bounded_decompress(
                body, kind, cfg.max_index_decompressed_bytes
            ).decode("utf-8", errors="replace")
        except ValueError:
            _bump(dropped, "index_decompress_failed")
            continue
        url = f"{dists}/{path}"
        anchors[f"{source}/{spec.label}/{path}"] = body
        stats["indexes_fetched"] += 1
        rs["indexes"].append(path)
        for st in parse_packages(text):
            stats["stanzas_parsed"] += 1
            rs["stanzas"] += 1
            pkg = st.get("Package", "")
            if not pkg or not spec.selects(pkg):
                continue
            if st.get("Architecture") not in (spec.arch, "all"):
                _bump(dropped, "other_architecture")
                continue
            stats["selected"] += 1
            rs["selected"] += 1
            out.append(_Cand(order, spec, comp, url, rel, inrel_sha, st))
    return out


def _validate(c: _Cand, dropped: dict[str, int]) -> bool:
    st = c.st
    if not all(st.get(k) for k in ("Package", "Version", "Architecture", "Filename")):
        _bump(dropped, "stanza_malformed")
        return False
    if not st.get("Size", "").isdigit():
        _bump(dropped, "stanza_malformed")
        return False
    try:
        parse_version(st["Version"])
    except ValueError:
        _bump(dropped, "bad_version")
        return False
    if not _safe_filename(st["Filename"]):
        _bump(dropped, "unsafe_filename")
        return False
    exp: dict[str, str] = {}
    for fld, alg in _HASH_FIELDS.items():
        v = st.get(fld, "").strip().lower()
        if v:
            exp[alg] = v
    if not exp:
        _bump(dropped, "stanza_no_sha256_sha512")
        return False
    c.expected = exp
    return True


def _item(c: _Cand, source: str) -> PlanItem:
    st = c.st
    return PlanItem(
        source=source,
        key=f"{source}:{c.spec.label}/{st['Package']}_{st['Version']}_"
        f"{st['Architecture']}",
        url=f"{c.spec.base_url}/{st['Filename']}",
        expected=c.expected,
        size=int(st["Size"]),
        meta={
            "package": st["Package"],
            "version": st["Version"],
            "architecture": st["Architecture"],
            "repo": c.spec.name,
            "suite": c.spec.suite,
            "component": c.component,
            "catalog_url": c.catalog_url,
            "source_date": c.release["date"],
            "date_kind": "apt_release_date_upper_bound",
            "release_sig": "unverified",
            "inrelease_sha256": c.inrelease_sha256,
            "vendor_evidence": {
                "maintainer": st.get("Maintainer"),
                "homepage": st.get("Homepage"),
                "source_package": st.get("Source"),
                "section": st.get("Section"),
            },
            "licence": None,
        },
    )


def _pkg_key(c: _Cand) -> tuple[str, str, str]:
    return (c.spec.name, c.spec.suite, c.st["Package"])


def _round_robin(cands: list[_Cand], n: int) -> set[tuple[str, str, str]]:
    """First ``n`` packages taken one per (repo, suite) group per round.

    Groups and the packages in each are in sorted order, so a smoke run with a
    small ``n`` still touches every host and suite, deterministically.
    """
    groups: dict[tuple[str, str], list[str]] = {}
    for k in sorted({_pkg_key(c) for c in cands}):
        groups.setdefault(k[:2], []).append(k[2])
    order = sorted(groups)
    allow: set[tuple[str, str, str]] = set()
    rnd = 0
    while len(allow) < n and any(rnd < len(groups[g]) for g in order):
        for g in order:
            if len(allow) >= n:
                break
            if rnd < len(groups[g]):
                allow.add((g[0], g[1], groups[g][rnd]))
        rnd += 1
    return allow


def plan_repos(get: Getter, config: AptConfig, source: str) -> CatalogResult:
    """Shared planner for apt-format repos; ``source`` labels keys and anchors."""
    anchors: dict[str, bytes] = {}
    dropped: dict[str, int] = {}
    stats: dict[str, Any] = {
        "indexes_fetched": 0,
        "stanzas_parsed": 0,
        "selected": 0,
        "per_repo": {},
    }
    cands: list[_Cand] = []
    for order, spec in enumerate(config.repos):
        got = _read_repo(get, spec, order, config, source, anchors, dropped, stats)
        cands.extend(c for c in got if _validate(c, dropped))

    # same .deb listed by two suites of one repo (noble vs noble-updates)
    seen: set[tuple[str, str, str]] = set()
    uniq: list[_Cand] = []
    for c in sorted(cands, key=lambda c: c.order):
        k = (
            c.spec.name,
            c.st["Filename"],
            c.expected.get("sha256") or c.expected["sha512"],
        )
        if k in seen:
            _bump(dropped, "duplicate_in_other_suite")
            continue
        seen.add(k)
        uniq.append(c)

    # newest N versions per (repo name, package)
    groups: dict[tuple[str, str], list[_Cand]] = {}
    for c in uniq:
        groups.setdefault((c.spec.name, c.st["Package"]), []).append(c)
    kept: list[_Cand] = []
    for gk in sorted(groups):
        g = sorted(groups[gk], key=lambda c: c.order)
        g.sort(key=lambda c: sort_key(c.st["Version"]), reverse=True)
        versions: list[str] = []
        for c in g:
            v = c.st["Version"]
            if v not in versions:
                if len(versions) >= config.versions_per_package:
                    _bump(dropped, "older_version")
                    continue
                versions.append(v)
            kept.append(c)

    # the same bytes reached through another repo
    seen_sha: set[str] = set()
    final: list[_Cand] = []
    for c in sorted(kept, key=lambda c: c.order):
        h = c.expected.get("sha256") or c.expected["sha512"]
        if h in seen_sha:
            _bump(dropped, "duplicate_sha256")
            continue
        seen_sha.add(h)
        final.append(c)
    stats["candidates"] = len(final)

    if config.max_packages is not None:
        allow = _round_robin(final, config.max_packages)
        cut = [c for c in final if _pkg_key(c) not in allow]
        if cut:
            _bump(dropped, "max_packages", len(cut))
        final = [c for c in final if _pkg_key(c) in allow]

    items: dict[str, PlanItem] = {}
    for c in final:
        try:
            it = _item(c, source)
        except ValueError:
            _bump(dropped, "bad_item")
            continue
        if it.key in items:
            _bump(dropped, "duplicate_key")
            continue
        items[it.key] = it
    ordered = tuple(items[k] for k in sorted(items))
    stats["items"] = len(ordered)
    return CatalogResult(
        source=source,
        items=ordered,
        anchors=anchors,
        dropped=dict(sorted(dropped.items())),
        stats=stats,
    )


def plan(get: Getter, config: AptConfig = DEFAULT_CONFIG) -> CatalogResult:
    """Plan the apt pull: one ``PlanItem`` per selected ``.deb``."""
    return plan_repos(get, config, SOURCE)

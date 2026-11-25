"""winget planner (W7): pinned commit -> manifest -> ``InstallerSha256`` -> installer.

The winget community repository (microsoft/winget-pkgs, MIT) lists Windows
installers with a SHA-256 per installer. The chain of trust is: a commit id (pinned
once; COLLECT §3 step 1), the repository tarball at that commit (its sha256 kept as
the anchor), the YAML manifests inside it, and each manifest's ``InstallerSha256``,
which the fetcher checks the downloaded installer against. Fetch-only (C20):
installers are downloaded and verified, never run and never unpacked here.

Why it looks like this:

- The tarball is untrusted and large (millions of members are possible), so it is
  read once in streaming mode (``r|gz``) from memory and never extracted. Only
  regular files under ``manifests/`` ending ``.yaml`` are considered; absolute names,
  ``..`` parts, links and devices are refused; every member and the total expanded
  size are bounded, and the gzip stream is checked to its end (CRC) before any
  member is trusted, so a truncated download cannot look like a short catalogue.
- Parsing every manifest would be slow and memory-hungry, so while streaming only
  the bytes of the current highest version folder of each package folder are kept.
  The folder name is the version (repo layout ``manifests/<l>/<Publisher>/.../
  <Version>/``): ``yaml.safe_load`` turns an unquoted ``PackageVersion: 1.10`` into
  the float 1.1, so the YAML scalar is only compared (``stats.version_mismatch``).
- Versions are loose strings; ``version_key`` splits them into digit and non-digit
  runs, compares digit runs as integers and other runs case-folded, a digit run
  sorting before a non-digit run in the same slot, and finally the raw string, so
  the order is total and independent of archive order. The highest version wins
  even if it is unusable (the package is then dropped, not silently downgraded).
- One installer per package: x64, then neutral, then x86 (arm/arm64 never); then
  msi/wix, msix/appx, zip/portable, exe/inno/nullsoft/burn; pwa and font never.
  ``InstallerType``, ``Scope`` and ``ReleaseDate`` may be set at the manifest root
  and are inherited by installers that do not set them. HTTPS URLs and a 64-hex
  SHA-256 only (MD5/SHA-1 never count).
- Selection is reproducible: duplicates of the same installer SHA-256 are kept once
  (lowest identifier), at most ``per_publisher_cap`` packages per publisher
  (``Random(f"{seed}:{publisher}")``), then a ``Random(seed)`` sample of
  ``max_packages`` (450 approved; going past it is open decision §8 Q13).
- Unknown or malformed manifests degrade to ``dropped[reason]``; a broken chain
  (bad commit id, unreadable or oversize tarball, commit mismatch, a bound hit)
  raises ``ValueError``: a partial catalogue would bias the plan silently.

Dates: ``ReleaseDate`` if present (optional in the schema; COLLECT §3), never an
inventory time (H6).
"""

from __future__ import annotations

import hashlib
import io
import json
import random
import re
import tarfile
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import yaml

from sherlock.collect.items import CatalogResult, Getter, PlanItem

__all__ = [
    "DEFAULT_CONFIG",
    "SOURCE",
    "WingetConfig",
    "plan",
    "version_key",
]

SOURCE = "winget"

#: Installer types worth fetching, best first within each rank. pwa (a web link)
#: and font are never collected.
_TYPE_RANK = {
    "msi": 0,
    "wix": 0,
    "msix": 1,
    "appx": 1,
    "zip": 2,
    "portable": 2,
    "exe": 3,
    "inno": 3,
    "nullsoft": 3,
    "burn": 3,
}
_ARCH_RANK = {"x64": 0, "neutral": 1, "x86": 2}

_SHA1_HEX = re.compile(r"^[0-9a-f]{40}$")
_SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
_SEG = r'[^.\s\\/:*?"<>|\x00-\x1f]{1,64}'
_IDENT = re.compile(rf"^{_SEG}(\.{_SEG}){{1,7}}$")
_VERSION = re.compile(r"^[^\s/\\\x00-\x1f]{1,128}$")
_CHUNK = 1 << 20


@dataclass(frozen=True)
class WingetConfig:
    """Knobs for one winget plan."""

    #: GitHub ``owner/name`` of the manifest repository (MIT licence).
    repo: str = "microsoft/winget-pkgs"
    #: Branch whose head is pinned when ``commit`` is None.
    branch: str = "master"
    #: 40-hex commit to plan from; None resolves the branch head once and pins it.
    commit: str | None = None
    #: Packages in the plan: 450 approved; past 450 is open (§8 Q13). --plan-limit.
    max_packages: int = 450
    #: At most this many packages per publisher, so one vendor cannot dominate.
    per_publisher_cap: int = 2
    #: Seed of the publisher-cap and final samples, so the plan is reproducible.
    seed: int = 0
    #: Bound on the commits API JSON (it carries file patches, so allow a few MiB).
    max_api_bytes: int = 8 << 20
    #: Bound on the compressed repository tarball (held in memory).
    max_tarball_bytes: int = 1536 << 20
    #: Bound on the decompressed tarball, against gzip bombs.
    max_expanded_bytes: int = 32 << 30
    #: Manifests above this are skipped (real ones are a few KiB).
    max_manifest_bytes: int = 1 << 20
    #: Stop (raise) past this many tar members.
    max_members: int = 2_000_000
    #: Files kept per version folder; a folder with more is dropped.
    max_files_per_folder: int = 64
    #: Total manifest bytes held while streaming (one folder per package).
    max_kept_bytes: int = 1 << 30
    #: Installer types eligible for the plan (subset of the ten fetchable ones).
    allowed_installer_types: tuple[str, ...] = tuple(_TYPE_RANK)

    def __post_init__(self) -> None:
        if not _REPO.match(self.repo) or ".." in self.repo:
            raise ValueError(f"repo must be 'owner/name', got {self.repo!r}")
        if not _BRANCH.match(self.branch) or ".." in self.branch:
            raise ValueError(f"branch has unsafe characters: {self.branch!r}")
        if self.commit is not None and not _SHA1_HEX.match(self.commit):
            raise ValueError("commit must be 40 lowercase hex characters or None")
        if self.max_packages < 0:
            raise ValueError("max_packages must be >= 0")
        if self.per_publisher_cap < 1:
            raise ValueError("per_publisher_cap must be >= 1")
        for name in (
            "max_api_bytes",
            "max_tarball_bytes",
            "max_expanded_bytes",
            "max_manifest_bytes",
            "max_members",
            "max_files_per_folder",
            "max_kept_bytes",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be >= 1")
        bad = set(self.allowed_installer_types) - set(_TYPE_RANK)
        if bad:
            raise ValueError(
                f"allowed_installer_types: {sorted(bad)} not fetchable; "
                f"choose from {sorted(_TYPE_RANK)}"
            )


DEFAULT_CONFIG = WingetConfig()


# -- versions --


def version_key(v: str) -> tuple[tuple[tuple[int, int, str], ...], str]:
    """Natural sort key: digit runs as integers, other runs case-folded, then raw.

    Tokens are ``(0, n, "")`` for digits and ``(1, 0, text)`` otherwise, so any two
    keys compare without a TypeError; the raw string breaks ties (``1.0`` vs
    ``1.00``) so the order is total.
    """
    toks = tuple(
        (0, int(t), "") if t.isdigit() else (1, 0, t.casefold())
        for t in re.findall(r"\d+|\D+", v)
    )
    return toks, v


# -- chain: commit and tarball --


def _resolve_commit(get: Getter, cfg: WingetConfig) -> str:
    url = f"https://api.github.com/repos/{cfg.repo}/commits/{cfg.branch}"
    body = get(url, cfg.max_api_bytes)
    if len(body) > cfg.max_api_bytes:
        raise ValueError(f"winget: commits API body over max_api_bytes ({url})")
    try:
        doc = json.loads(body)
    except ValueError as e:
        raise ValueError(f"winget: commits API did not return JSON ({url}): {e}") from e
    sha = doc.get("sha") if isinstance(doc, dict) else None
    if not isinstance(sha, str) or not _SHA1_HEX.match(sha):
        raise ValueError(f"winget: commits API sha is not 40 lowercase hex: {sha!r}")
    return sha


def _check_gzip(tb: bytes, cfg: WingetConfig) -> int:
    """Decompress once without keeping output: CRC to the end, size bounded."""
    d = zlib.decompressobj(wbits=31)
    total = 0
    try:
        for i in range(0, len(tb), _CHUNK):
            buf = tb[i : i + _CHUNK]
            while buf:
                out = d.decompress(buf, _CHUNK)
                total += len(out)
                if total > cfg.max_expanded_bytes:
                    raise ValueError(
                        f"winget: tarball expands past max_expanded_bytes "
                        f"({cfg.max_expanded_bytes})"
                    )
                buf = d.unconsumed_tail
            if d.eof:
                break
        while not d.eof:
            out = d.decompress(b"", _CHUNK)
            if not out:
                break
            total += len(out)
            if total > cfg.max_expanded_bytes:
                raise ValueError("winget: tarball expands past max_expanded_bytes")
    except zlib.error as e:
        raise ValueError(f"winget: tarball is not valid gzip: {e}") from e
    if not d.eof:
        raise ValueError("winget: tarball gzip stream is truncated")
    return total


# -- streaming the tar --


@dataclass
class _Folder:
    key: tuple[Any, ...]
    version: str
    path: str  # repo path of the version folder
    files: dict[str, bytes] = field(default_factory=dict)
    overflow: bool = False


@dataclass
class _Scan:
    folders: dict[str, _Folder] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)
    members_seen: int = 0
    members_other: int = 0
    manifest_members: int = 0
    kept_bytes: int = 0
    pax_comment: str | None = None


def _drop(d: dict[str, int], reason: str, n: int = 1) -> None:
    d[reason] = d.get(reason, 0) + n


def _safe_rel(name: str, top: str) -> str | None:
    """Path below the single top folder, or None if the name is unsafe."""
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return None
    parts = name.split("/")
    if parts[0] != top or len(parts) < 2:
        return None
    rest = parts[1:]
    if any(p in ("", ".", "..") for p in rest):
        return None
    return "/".join(rest)


def _scan_tar(tb: bytes, cfg: WingetConfig) -> _Scan:
    sc = _Scan()
    expanded = 0
    top: str | None = None
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r|gz")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise ValueError(f"winget: tarball is not a readable tar.gz: {e}") from e
    with tf:
        while True:
            try:
                m = tf.next()
            except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
                raise ValueError(f"winget: tarball read failed: {e}") from e
            tf.members = []  # type: ignore[attr-defined]  # never accumulate TarInfo
            if m is None:
                break
            sc.members_seen += 1
            if sc.members_seen > cfg.max_members:
                raise ValueError(
                    f"winget: tarball has more than max_members "
                    f"({cfg.max_members}) members"
                )
            expanded += max(m.size, 0)
            if expanded > cfg.max_expanded_bytes:
                raise ValueError("winget: member sizes exceed max_expanded_bytes")
            if top is None:
                top = m.name.split("/")[0]
            if m.isdir():
                continue
            if not m.isreg():
                _drop(sc.dropped, "unsafe_member")
                continue
            rel = _safe_rel(m.name, top)
            if rel is None:
                _drop(sc.dropped, "unsafe_member")
                continue
            if not rel.startswith("manifests/") or not rel.endswith(".yaml"):
                sc.members_other += 1
                continue
            sc.manifest_members += 1
            parts = rel.split("/")
            if len(parts) < 6:
                _drop(sc.dropped, "bad_layout")
                continue
            if m.size > cfg.max_manifest_bytes:
                _drop(sc.dropped, "manifest_too_large")
                continue
            version = parts[-2]
            pkg_dir = "/".join(parts[:-2])
            key = version_key(version)
            cur = sc.folders.get(pkg_dir)
            if cur is not None and key < cur.key:
                continue
            if cur is None or key > cur.key:
                if cur is not None:
                    sc.kept_bytes -= sum(len(b) for b in cur.files.values())
                cur = _Folder(key=key, version=version, path="/".join(parts[:-1]))
                sc.folders[pkg_dir] = cur
            fname = parts[-1]
            try:
                fh = tf.extractfile(m)
                data = fh.read(cfg.max_manifest_bytes + 1) if fh else b""
            except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
                raise ValueError(f"winget: tarball read failed: {e}") from e
            # non-default locales are never needed; skip their bytes
            if ".locale." in fname and b"defaultLocale" not in data:
                continue
            if cur.overflow:
                continue
            if len(cur.files) >= cfg.max_files_per_folder:
                cur.overflow = True
                sc.kept_bytes -= sum(len(b) for b in cur.files.values())
                cur.files = {}
                continue
            cur.files[fname] = data
            sc.kept_bytes += len(data)
            if sc.kept_bytes > cfg.max_kept_bytes:
                raise ValueError(
                    f"winget: kept manifests exceed max_kept_bytes "
                    f"({cfg.max_kept_bytes})"
                )
        comment = tf.pax_headers.get("comment")
        sc.pax_comment = comment if isinstance(comment, str) else None
    return sc


# -- manifests --


def _load(data: bytes) -> Any:
    """``yaml.safe_load`` only; any failure is a parse error."""
    return yaml.safe_load(data)


def _s(v: Any) -> str | None:
    """A scalar as a stripped string; None for missing or non-scalar values."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, str | int | float):
        out = str(v).strip()
        return out or None
    return None


def _iso_date(v: Any) -> str | None:
    if isinstance(v, datetime):
        return v.date().isoformat()
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, str):
        try:
            return date.fromisoformat(v.strip()).isoformat()
        except ValueError:
            return None
    return None


def _https(url: Any) -> bool:
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    if any(c.isspace() or ord(c) < 32 for c in url):
        return False
    try:
        return bool(urlsplit(url).hostname)
    except ValueError:
        return False


def _choose_installer(
    doc: Mapping[str, Any], allowed: Sequence[str]
) -> tuple[dict[str, Any] | None, str]:
    """Best installer (fields resolved against the root), or None and a reason."""
    insts = doc.get("Installers")
    if not isinstance(insts, list) or not insts:
        return None, "no_installers"
    arch_ok: list[tuple[int, dict[str, Any]]] = []
    for inst in insts:
        if not isinstance(inst, dict):
            continue
        arch = _s(inst.get("Architecture"))
        if arch is not None and arch.casefold() in _ARCH_RANK:
            arch_ok.append((_ARCH_RANK[arch.casefold()], inst))
    if not arch_ok:
        return None, "no_supported_architecture"
    ranked: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for arank, inst in arch_ok:
        itype = _s(inst.get("InstallerType", doc.get("InstallerType")))
        itype = itype.casefold() if itype else None
        if itype is None or itype not in allowed:
            continue
        url = inst.get("InstallerUrl")
        sha = inst.get("InstallerSha256")
        resolved = {
            "architecture": [k for k, r in _ARCH_RANK.items() if r == arank][0],
            "installer_type": itype,
            "url": url,
            "sha256": sha.lower() if isinstance(sha, str) else None,
            "scope": _s(inst.get("Scope", doc.get("Scope"))),
            "release_date": _iso_date(inst.get("ReleaseDate"))
            or _iso_date(doc.get("ReleaseDate")),
            "url_ok": _https(url) and str(url).isascii(),
            "url_non_ascii": _https(url) and not str(url).isascii(),
            "sha_ok": isinstance(sha, str) and bool(_SHA256_HEX.match(sha)),
        }
        rank = (arank, _TYPE_RANK[itype], str(url), str(sha))
        ranked.append((rank, resolved))
    if not ranked:
        return None, "installer_type_excluded"
    ranked.sort(key=lambda t: t[0])
    for _, r in ranked:
        if r["url_ok"] and r["sha_ok"]:
            return r, ""
    best = ranked[0][1]
    if best["url_non_ascii"]:
        return None, "non_ascii_url"
    return None, "not_https" if not best["url_ok"] else "no_sha256"


def _mtype(doc: Mapping[str, Any]) -> str:
    return (_s(doc.get("ManifestType")) or "").casefold()


@dataclass
class _Pkg:
    ident: str
    version: str
    publisher: str
    package_name: str | None
    licence: str | None
    publisher_url: str | None
    manifest_path: str
    inst: dict[str, Any]


def _read_folder(
    folder: _Folder, allowed: Sequence[str], stats: dict[str, int]
) -> tuple[_Pkg | None, str]:
    if folder.overflow:
        return None, "too_many_files"
    if not _VERSION.match(folder.version):
        return None, "bad_version"
    docs: list[tuple[str, dict[str, Any]]] = []
    for fname in sorted(folder.files):
        try:
            doc = _load(folder.files[fname])
        except Exception:  # noqa: BLE001 - any parse failure is a drop, never fatal
            return None, "yaml_error"
        stats["manifests_parsed"] += 1
        if not isinstance(doc, dict):
            return None, "bad_manifest"
        docs.append((fname, doc))
    single = [d for d in docs if _mtype(d[1]) == "singleton"]
    if single:
        if len(single) > 1:
            return None, "ambiguous_manifest"
        inst_name, inst_doc = single[0]
        loc_doc = inst_doc
    else:
        insts = [d for d in docs if _mtype(d[1]) == "installer"]
        locs = [d for d in docs if _mtype(d[1]) == "defaultlocale"]
        if not insts:
            return None, "no_installer_manifest"
        if len(insts) > 1 or len(locs) > 1:
            return None, "ambiguous_manifest"
        if not locs:
            return None, "no_default_locale"
        inst_name, inst_doc = insts[0]
        loc_doc = locs[0][1]
    ident = inst_doc.get("PackageIdentifier")
    if not isinstance(ident, str) or not _IDENT.match(ident):
        return None, "bad_identifier"
    if loc_doc.get("PackageIdentifier") != ident:
        return None, "inconsistent_manifest"
    if _s(inst_doc.get("PackageVersion")) != folder.version:
        stats["version_mismatch"] += 1
    publisher = _s(loc_doc.get("Publisher"))
    if publisher is None:
        return None, "no_publisher"
    inst, reason = _choose_installer(inst_doc, allowed)
    if inst is None:
        return None, reason
    return (
        _Pkg(
            ident=ident,
            version=folder.version,
            publisher=publisher,
            package_name=_s(loc_doc.get("PackageName")),
            licence=_s(loc_doc.get("License")),
            publisher_url=_s(loc_doc.get("PublisherUrl")),
            manifest_path=f"{folder.path}/{inst_name}",
            inst=inst,
        ),
        "",
    )


def _norm_pub(p: str) -> str:
    return p.casefold().strip()


# -- plan --


def plan(get: Getter, config: WingetConfig = DEFAULT_CONFIG) -> CatalogResult:
    """Plan installer downloads from winget-pkgs at one pinned commit."""
    cfg = config
    sha = cfg.commit if cfg.commit is not None else _resolve_commit(get, cfg)
    if not _SHA1_HEX.match(sha):
        raise ValueError(f"winget: commit is not 40 lowercase hex: {sha!r}")
    tar_url = f"https://codeload.github.com/{cfg.repo}/tar.gz/{sha}"
    tb = get(tar_url, cfg.max_tarball_bytes)
    if len(tb) > cfg.max_tarball_bytes:
        raise ValueError(
            f"winget: tarball is {len(tb)} bytes, over max_tarball_bytes "
            f"({cfg.max_tarball_bytes})"
        )
    tb_sha = hashlib.sha256(tb).hexdigest()
    expanded = _check_gzip(tb, cfg)
    sc = _scan_tar(tb, cfg)
    if sc.pax_comment is not None and sc.pax_comment != sha:
        raise ValueError(
            f"winget: tarball commit {sc.pax_comment!r} is not the pinned commit {sha}"
        )

    dropped = dict(sc.dropped)
    counts = {"manifests_parsed": 0, "version_mismatch": 0}
    allowed = tuple(t.casefold() for t in cfg.allowed_installer_types)

    # highest version per identifier (case-insensitive, like winget)
    by_id: dict[str, tuple[tuple[Any, ...], str, _Pkg]] = {}
    for pkg_dir in sorted(sc.folders):
        folder = sc.folders[pkg_dir]
        pkg, reason = _read_folder(folder, allowed, counts)
        if pkg is None:
            _drop(dropped, reason)
            continue
        k = pkg.ident.casefold()
        cand = (folder.key, pkg_dir, pkg)
        prev = by_id.get(k)
        if prev is None:
            by_id[k] = cand
        else:
            _drop(dropped, "duplicate_identifier")
            if (cand[0], cand[1]) > (prev[0], prev[1]):
                by_id[k] = cand
    n_folders = len(sc.folders)
    sc.folders.clear()  # release manifest bytes
    pkgs = sorted((v[2] for v in by_id.values()), key=lambda p: p.ident.casefold())

    # same installer bytes listed twice: keep the lowest identifier
    seen_sha: set[str] = set()
    eligible: list[_Pkg] = []
    for p in pkgs:
        if p.inst["sha256"] in seen_sha:
            _drop(dropped, "duplicate_installer")
            continue
        seen_sha.add(p.inst["sha256"])
        eligible.append(p)

    by_pub: dict[str, list[_Pkg]] = {}
    for p in eligible:
        by_pub.setdefault(_norm_pub(p.publisher), []).append(p)
    capped: list[_Pkg] = []
    for pub in sorted(by_pub):
        group = by_pub[pub]
        if len(group) > cfg.per_publisher_cap:
            _drop(dropped, "publisher_cap", len(group) - cfg.per_publisher_cap)
            group = random.Random(f"{cfg.seed}:{pub}").sample(
                group, cfg.per_publisher_cap
            )
        capped.extend(group)
    capped.sort(key=lambda p: p.ident.casefold())
    n = min(cfg.max_packages, len(capped))
    chosen = random.Random(cfg.seed).sample(capped, n)
    chosen.sort(key=lambda p: p.ident.casefold())

    items: list[PlanItem] = []
    for p in chosen:
        inst = p.inst
        date_str = inst["release_date"]
        try:
            items.append(
                PlanItem(
                    source=SOURCE,
                    key=f"winget:{p.ident}/{p.version}",
                    url=inst["url"],
                    expected={"sha256": inst["sha256"]},
                    size=None,
                    meta={
                        "package": p.ident,
                        "version": p.version,
                        "publisher": p.publisher,
                        "package_name": p.package_name,
                        "licence": p.licence,
                        "installer_type": inst["installer_type"],
                        "architecture": inst["architecture"],
                        "scope": inst["scope"],
                        "catalog_url": (
                            f"https://github.com/{cfg.repo}/blob/{sha}/"
                            f"{quote(p.manifest_path, safe='/')}"
                        ),
                        "commit": sha,
                        "source_date": date_str,
                        "date_kind": "winget_release_date" if date_str else None,
                        "vendor_evidence": {
                            "publisher": p.publisher,
                            "publisher_url": p.publisher_url,
                            "installer_host": urlsplit(inst["url"]).hostname,
                        },
                    },
                )
            )
        except ValueError:
            _drop(dropped, "invalid_item")

    anchor = {
        "repo": cfg.repo,
        "branch": cfg.branch,
        "commit": sha,
        "commit_pinned_by_config": cfg.commit is not None,
        "tarball_url": tar_url,
        "tarball_sha256": tb_sha,
        "tarball_bytes": len(tb),
        "tar_pax_commit": sc.pax_comment,
    }
    stats = {
        "commit": sha,
        "tarball_sha256": tb_sha,
        "tarball_bytes": len(tb),
        "tarball_expanded_bytes": expanded,
        "tar_pax_commit_matches": sc.pax_comment == sha,
        "members_seen": sc.members_seen,
        "members_other": sc.members_other,
        "manifest_members": sc.manifest_members,
        "manifests_parsed": counts["manifests_parsed"],
        "version_mismatch": counts["version_mismatch"],
        "packages": n_folders,
        "packages_parsed": len(by_id),
        "eligible": len(eligible),
        "publishers": len(by_pub),
        "after_publisher_cap": len(capped),
        "selected": len(items),
    }
    return CatalogResult(
        source=SOURCE,
        items=tuple(items),
        anchors={"winget_commit.json": json.dumps(anchor, sort_keys=True).encode()},
        dropped=dict(sorted(dropped.items())),
        stats=stats,
    )

"""apt/PMC planner: InRelease -> Packages SHA256/SHA512 -> .deb, fully offline."""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import lzma

import pytest

from sherlock.collect.catalog import apt, pmc
from sherlock.collect.catalog.apt import (
    AptConfig,
    RepoSpec,
    bounded_decompress,
    parse_clearsigned,
    parse_packages,
)
from sherlock.collect.items import CatalogResult

BASE = "https://mirror.example.test/debian"
BASE2 = "https://other.example.test/ubuntu"


# -- synthetic catalogue builders --


def _sha(b: bytes, alg: str = "sha256") -> str:
    return hashlib.new(alg, b).hexdigest()


def _stanza(
    pkg: str,
    ver: str,
    arch: str = "amd64",
    body: bytes | None = None,
    filename: str | None = None,
    sha512: bool = True,
    sha256: bool = True,
    extra: str = "",
) -> str:
    deb = body if body is not None else f"{pkg}-{ver}-{arch}".encode()
    fn = filename or f"pool/main/{pkg[0]}/{pkg}/{pkg}_{ver}_{arch}.deb"
    lines = [
        f"Package: {pkg}",
        f"Version: {ver}",
        f"Architecture: {arch}",
        "Maintainer: Example Maintainers <team@example.test>",
        f"Source: {pkg}-src",
        "Section: libs",
        "Homepage: https://www.example.test/",
        "Description: synthetic package",
        " continuation line one",
        " .",
        " continuation line two",
        f"Filename: {fn}",
        f"Size: {len(deb)}",
        f"MD5sum: {hashlib.md5(deb).hexdigest()}",
    ]
    if sha256:
        lines.append(f"SHA256: {_sha(deb)}")
    if sha512:
        lines.append(f"SHA512: {_sha(deb, 'sha512')}")
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def _packages(*stanzas: str) -> bytes:
    return "\n".join(stanzas).encode()


def _release_body(
    files: dict[str, bytes], algs=("SHA256",), date="Sat, 21 Nov 2026 08:15:00 UTC"
) -> str:
    out = [
        "Origin: Example",
        "Suite: testing",
        "Codename: trixie",
        f"Date: {date}",
        "Valid-Until: Sat, 28 Nov 2026 08:15:00 UTC",
        "Architectures: amd64 arm64",
        "Components: main contrib",
        "Description: - a dash-leading description",
    ]
    for alg in algs:
        out.append(f"{alg}:" if alg != "MD5Sum" else "MD5Sum:")
        h = {"SHA256": "sha256", "SHA512": "sha512", "MD5Sum": "md5", "SHA1": "sha1"}
        for path, data in sorted(files.items()):
            out.append(
                f" {hashlib.new(h[alg], data).hexdigest()} {len(data):>9} {path}"
            )
    return "\n".join(out) + "\n"


def _clearsign(body: str) -> bytes:
    escaped = "\n".join(
        ("- " + ln) if ln.startswith("-") else ln for ln in body.splitlines()
    )
    return (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        + escaped
        + "\n-----BEGIN PGP SIGNATURE-----\n\niQIzBAEBCgAdFiEEsynthetic\n=abcd\n"
        "-----END PGP SIGNATURE-----\n"
    ).encode()


def _repo(
    base: str,
    suite: str,
    comps: dict[str, bytes],
    algs=("SHA256",),
    compress: str = "xz",
    listed: dict[str, bytes] | None = None,
    served: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    """comps: component -> plain Packages bytes. Returns url -> bytes."""
    files: dict[str, bytes] = {}
    for comp, plain in comps.items():
        if compress == "xz":
            files[f"{comp}/binary-amd64/Packages.xz"] = lzma.compress(plain)
        elif compress == "gz":
            files[f"{comp}/binary-amd64/Packages.gz"] = gzip.compress(plain)
        else:
            files[f"{comp}/binary-amd64/Packages"] = plain
    release_files = dict(files) if listed is None else listed
    urls = {
        f"{base}/dists/{suite}/InRelease": _clearsign(
            _release_body(release_files, algs)
        )
    }
    for path, data in (served if served is not None else files).items():
        urls[f"{base}/dists/{suite}/{path}"] = data
    return urls


class FakeGetter:
    def __init__(self, urls: dict[str, bytes]):
        self.urls = urls
        self.calls: list[str] = []

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        if url not in self.urls:
            raise OSError(f"404 {url}")
        body = self.urls[url]
        if len(body) > max_bytes:
            raise ValueError("oversize")
        return body


def _cfg(*repos: RepoSpec, **kw) -> AptConfig:
    return AptConfig(repos=tuple(repos), **kw)


def _spec(
    name="deb",
    base=BASE,
    suite="trixie",
    comps=("main",),
    select=(r".*",),
    exclude=(r".*-(dbg|dbgsym|doc)",),
) -> RepoSpec:
    return RepoSpec(
        name=name,
        base_url=base,
        suite=suite,
        components=comps,
        select=select,
        exclude=exclude,
    )


# -- clearsigned / release --


def test_clearsigned_body_parsed():
    body = "Origin: X\nDescription: - leading dash\n-- double\nDate: d\n"
    raw = _clearsign(body)
    assert b"\n- - leading" not in raw  # sanity: field line itself not dash-led
    assert b"- -- double" in raw
    assert parse_clearsigned(raw) == body.rstrip("\n") + "\n"


def test_not_clearsigned_rejected():
    with pytest.raises(ValueError):
        parse_clearsigned(b"Origin: X\nDate: d\n")
    with pytest.raises(ValueError):  # no signature block
        parse_clearsigned(b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nA: b\n")


def test_release_sig_marked_unverified_and_inrelease_kept_as_anchor():
    pk = _packages(_stanza("mono-runtime", "6.12.0-1"))
    urls = _repo(BASE, "trixie", {"main": pk})
    res = apt.plan(FakeGetter(urls), _cfg(_spec()))
    assert isinstance(res, CatalogResult)
    assert len(res.items) == 1
    it = res.items[0]
    inrel = urls[f"{BASE}/dists/trixie/InRelease"]
    assert res.anchors["apt/deb/trixie/InRelease"] == inrel
    assert (
        res.anchors["apt/deb/trixie/main/binary-amd64/Packages.xz"]
        == urls[f"{BASE}/dists/trixie/main/binary-amd64/Packages.xz"]
    )
    m = it.meta
    assert m["release_sig"] == "unverified"
    assert m["inrelease_sha256"] == _sha(inrel)
    assert m["source_date"] == "2026-11-21"
    assert m["date_kind"] == "apt_release_date_upper_bound"
    assert m["catalog_url"] == f"{BASE}/dists/trixie/main/binary-amd64/Packages.xz"
    assert m["package"] == "mono-runtime" and m["version"] == "6.12.0-1"
    assert m["component"] == "main" and m["repo"] == "deb" and m["suite"] == "trixie"
    assert m["licence"] is None
    assert m["vendor_evidence"]["maintainer"].startswith("Example Maintainers")
    assert m["vendor_evidence"]["source_package"] == "mono-runtime-src"
    assert it.key == "apt:deb/trixie/mono-runtime_6.12.0-1_amd64"
    assert it.url == f"{BASE}/pool/main/m/mono-runtime/mono-runtime_6.12.0-1_amd64.deb"
    assert set(it.expected) == {"sha256", "sha512"}
    assert it.size == len(b"mono-runtime-6.12.0-1-amd64")
    assert res.stats["per_repo"]["deb/trixie"]["valid_until"] == "2026-11-28"


def test_sha512_only_release_accepted():
    pk = _packages(_stanza("wine", "10.0-1"))
    urls = _repo(BASE, "trixie", {"main": pk}, algs=("SHA512",))
    res = apt.plan(FakeGetter(urls), _cfg(_spec()))
    assert len(res.items) == 1


def test_md5_sha1_never_suffice():
    pk = _packages(_stanza("wine", "10.0-1"))
    urls = _repo(BASE, "trixie", {"main": pk}, algs=("MD5Sum", "SHA1"))
    g = FakeGetter(urls)
    res = apt.plan(g, _cfg(_spec()))
    assert res.items == ()
    assert res.dropped.get("index_weak_digest_only") == 1
    assert not any("Packages" in c for c in g.calls)  # never fetched


def test_stanza_without_strong_digest_dropped():
    pk = _packages(
        _stanza("wine", "10.0-1", sha256=False, sha512=False),
        _stanza("winetricks", "1-1"),
    )
    res = apt.plan(FakeGetter(_repo(BASE, "trixie", {"main": pk})), _cfg(_spec()))
    assert [i.meta["package"] for i in res.items] == ["winetricks"]
    assert res.dropped.get("stanza_no_sha256_sha512") == 1


def test_index_missing_from_release_dropped():
    pk = _packages(_stanza("wine", "10.0-1"))
    urls = _repo(BASE, "trixie", {"main": pk}, listed={})
    res = apt.plan(FakeGetter(urls), _cfg(_spec()))
    assert res.items == ()
    assert res.dropped.get("index_not_in_release") == 1


def test_packages_digest_mismatch_drops_index():
    good = _packages(_stanza("wine", "10.0-1"))
    evil = _packages(_stanza("wine", "10.0-1", body=b"tampered"))
    listed = {
        "main/binary-amd64/Packages.xz": lzma.compress(good),
        "contrib/binary-amd64/Packages.xz": lzma.compress(good),
    }
    served = {
        "main/binary-amd64/Packages.xz": lzma.compress(evil),
        "contrib/binary-amd64/Packages.xz": lzma.compress(good),
    }
    urls = _repo(BASE, "trixie", {}, listed=listed, served=served)
    res = apt.plan(FakeGetter(urls), _cfg(_spec(comps=("main", "contrib"))))
    assert res.dropped.get("index_digest_mismatch") == 1
    assert [i.meta["component"] for i in res.items] == ["contrib"]
    assert "apt/deb/trixie/main/binary-amd64/Packages.xz" not in res.anchors


def test_index_falls_back_to_gz_then_plain():
    pk = _packages(_stanza("wine", "10.0-1"))
    for comp in ("gz", "plain"):
        res = apt.plan(
            FakeGetter(_repo(BASE, "trixie", {"main": pk}, compress=comp)),
            _cfg(_spec()),
        )
        assert len(res.items) == 1, comp


def test_decompression_bounded():
    big = b"A" * 100_000
    assert bounded_decompress(lzma.compress(big), "xz", 200_000) == big
    assert bounded_decompress(gzip.compress(big), "gz", 200_000) == big
    with pytest.raises(ValueError):
        bounded_decompress(lzma.compress(big), "xz", 50_000)
    with pytest.raises(ValueError):
        bounded_decompress(gzip.compress(big), "gz", 50_000)
    with pytest.raises(ValueError):  # truncated stream
        bounded_decompress(lzma.compress(big)[:-20], "xz", 200_000)
    pk = _packages(_stanza("wine", "10.0-1"), "X-Pad: " + "p" * 10_000 + "\n")
    res = apt.plan(
        FakeGetter(_repo(BASE, "trixie", {"main": pk})),
        _cfg(_spec(), max_index_decompressed_bytes=1_000),
    )
    assert res.items == ()
    assert res.dropped.get("index_decompress_failed") == 1


def test_parse_packages_continuations_and_stanzas():
    st = parse_packages(_packages(_stanza("a", "1"), _stanza("b", "2")).decode())
    assert [s["Package"] for s in st] == ["a", "b"]
    assert "continuation line two" in st[0]["Description"]


# -- selection --


def test_filename_traversal_dropped():
    bad = [
        "../../etc/passwd.deb",
        "/abs/x.deb",
        "https://evil.test/x.deb",
        "pool/../../x.deb",
        "pool\\x.deb",
    ]
    st = [_stanza(f"wine{i}", "1-1", filename=f) for i, f in enumerate(bad)]
    st.append(_stanza("wine-ok", "1-1"))
    res = apt.plan(
        FakeGetter(_repo(BASE, "trixie", {"main": _packages(*st)})), _cfg(_spec())
    )
    assert [i.meta["package"] for i in res.items] == ["wine-ok"]
    assert res.dropped.get("unsafe_filename") == len(bad)


def test_select_and_exclude():
    pk = _packages(
        _stanza("libmono-system-cil", "6.12-1", arch="all"),
        _stanza("wine-dbg", "1-1"),
        _stanza("bash", "5-1"),
        _stanza("wine", "1-1", arch="i386"),
    )
    spec = _spec(select=(r"libmono-.*-cil", r"wine.*"))
    res = apt.plan(FakeGetter(_repo(BASE, "trixie", {"main": pk})), _cfg(spec))
    assert [i.meta["package"] for i in res.items] == ["libmono-system-cil"]
    assert res.items[0].meta["architecture"] == "all"


def test_newest_version_kept():
    pk = _packages(
        _stanza("dotnet-sdk-8.0", "8.0.110-1"),
        _stanza("dotnet-sdk-8.0", "8.0.111-1"),
        _stanza("dotnet-sdk-8.0", "8.0.111~rc1-1"),
        _stanza("dotnet-sdk-8.0", "8.0.99-1"),
    )
    res = apt.plan(FakeGetter(_repo(BASE, "trixie", {"main": pk})), _cfg(_spec()))
    assert [i.meta["version"] for i in res.items] == ["8.0.111-1"]
    assert res.dropped.get("older_version") == 3
    res2 = apt.plan(
        FakeGetter(_repo(BASE, "trixie", {"main": pk})),
        _cfg(_spec(), versions_per_package=2),
    )
    assert sorted(i.meta["version"] for i in res2.items) == [
        "8.0.111-1",
        "8.0.111~rc1-1",
    ]


def test_newest_version_across_suites_and_duplicates():
    same = _stanza("shim-signed", "1.58+15.8-0ubuntu1")
    newer = _stanza("dotnet8", "8.0.11-0ubuntu1")
    older = _stanza("dotnet8", "8.0.11-0ubuntu1~24.04.1")
    urls = _repo(BASE2, "noble", {"main": _packages(same, older)})
    urls.update(_repo(BASE2, "noble-updates", {"main": _packages(same, newer)}))
    cfg = _cfg(
        _spec(name="ubuntu", base=BASE2, suite="noble"),
        _spec(name="ubuntu", base=BASE2, suite="noble-updates"),
    )
    res = apt.plan(FakeGetter(urls), cfg)
    got = {(i.meta["package"], i.meta["version"], i.meta["suite"]) for i in res.items}
    assert got == {
        ("shim-signed", "1.58+15.8-0ubuntu1", "noble"),
        ("dotnet8", "8.0.11-0ubuntu1", "noble-updates"),
    }
    assert res.dropped.get("duplicate_in_other_suite") == 1
    assert res.dropped.get("older_version") == 1


def test_same_deb_across_repos_deduped_by_sha256():
    st = _stanza("wine", "10.0-1", body=b"identical-deb")
    urls = _repo(BASE, "trixie", {"main": _packages(st)})
    urls.update(_repo(BASE2, "noble", {"main": _packages(st)}))
    cfg = _cfg(_spec(), _spec(name="ubuntu", base=BASE2, suite="noble"))
    res = apt.plan(FakeGetter(urls), cfg)
    assert len(res.items) == 1
    assert res.dropped.get("duplicate_sha256") == 1


def test_one_repo_failing_keeps_others():
    ok = _repo(BASE, "trixie", {"main": _packages(_stanza("wine", "10.0-1"))})
    cfg = _cfg(_spec(name="gone", base=BASE2, suite="noble"), _spec())
    res = apt.plan(FakeGetter(ok), cfg)
    assert len(res.items) == 1
    assert res.dropped.get("repo_failed:gone/noble") == 1
    # a garbage InRelease also fails just that repo
    bad = dict(ok)
    bad[f"{BASE2}/dists/noble/InRelease"] = b"not clearsigned"
    res = apt.plan(FakeGetter(bad), cfg)
    assert len(res.items) == 1
    assert res.dropped.get("repo_failed:gone/noble") == 1
    # an index fetch failure drops the index, not the run
    miss = dict(ok)
    del miss[f"{BASE}/dists/trixie/main/binary-amd64/Packages.xz"]
    res = apt.plan(FakeGetter(miss), _cfg(_spec()))
    assert res.items == () and res.dropped.get("index_fetch_failed") == 1


def test_arch_not_in_release_fails_repo():
    urls = _repo(BASE, "trixie", {"main": _packages(_stanza("wine", "1-1"))})
    spec = RepoSpec(
        name="deb",
        base_url=BASE,
        suite="trixie",
        components=("main",),
        arch="riscv64",
        select=(".*",),
    )
    res = apt.plan(FakeGetter(urls), _cfg(spec))
    assert res.items == () and res.dropped.get("arch_not_in_release") == 1


def test_release_without_architectures_field_not_gated():
    urls = _repo(BASE, "trixie", {"main": _packages(_stanza("wine", "1-1"))})
    key = f"{BASE}/dists/trixie/InRelease"
    body = apt.parse_clearsigned(urls[key]).replace("Architectures: amd64 arm64\n", "")
    urls[key] = _clearsign(body)
    res = apt.plan(FakeGetter(urls), _cfg(_spec()))
    assert len(res.items) == 1
    assert "arch_not_in_release" not in res.dropped


def test_max_packages_limit():
    pk = _packages(
        *[_stanza(f"wine{c}", "1-1") for c in "dcba"], _stanza("winea", "0.9-1")
    )
    res = apt.plan(
        FakeGetter(_repo(BASE, "trixie", {"main": pk})), _cfg(_spec(), max_packages=2)
    )
    assert [i.meta["package"] for i in res.items] == ["winea", "wineb"]
    assert res.dropped.get("max_packages") == 2
    assert res.stats["selected"] == 5
    assert res.stats["candidates"] == 4


def test_max_packages_round_robin_across_repo_suites():
    def pk(prefix):
        return _packages(*[_stanza(f"{prefix}{c}", "1-1") for c in "abc"])

    urls = _repo(BASE, "trixie", {"main": pk("wine")})
    urls.update(_repo(BASE2, "noble", {"main": pk("mono-")}))
    urls.update(_repo(BASE2, "noble-updates", {"main": pk("dotnet")}))
    cfg = _cfg(
        _spec(),
        _spec(name="ubuntu", base=BASE2, suite="noble"),
        _spec(name="ubuntu", base=BASE2, suite="noble-updates"),
    )
    res = apt.plan(FakeGetter(urls), dataclasses.replace(cfg, max_packages=3))
    got = sorted(
        (i.meta["repo"], i.meta["suite"], i.meta["package"]) for i in res.items
    )
    assert got == [
        ("deb", "trixie", "winea"),
        ("ubuntu", "noble", "mono-a"),
        ("ubuntu", "noble-updates", "dotneta"),
    ]
    res = apt.plan(FakeGetter(urls), dataclasses.replace(cfg, max_packages=5))
    got = sorted((i.meta["suite"], i.meta["package"]) for i in res.items)
    assert got == [
        ("noble", "mono-a"),
        ("noble", "mono-b"),
        ("noble-updates", "dotneta"),
        ("trixie", "winea"),
        ("trixie", "wineb"),
    ]
    assert res.dropped.get("max_packages") == 4


def test_items_sorted_and_deterministic():
    pk = _packages(*[_stanza(f"wine{c}", "1-1") for c in "cab"])
    urls = _repo(BASE, "trixie", {"main": pk})
    a = apt.plan(FakeGetter(urls), _cfg(_spec()))
    b = apt.plan(FakeGetter(urls), _cfg(_spec()))
    assert [i.key for i in a.items] == sorted(i.key for i in a.items)
    assert a.items == b.items


def test_stats_counts():
    pk = _packages(_stanza("wine", "1-1"), _stanza("bash", "5-1"))
    res = apt.plan(
        FakeGetter(_repo(BASE, "trixie", {"main": pk})), _cfg(_spec(select=("wine",)))
    )
    assert res.stats["indexes_fetched"] == 1
    assert res.stats["stanzas_parsed"] == 2
    assert res.stats["selected"] == 1
    assert res.stats["per_repo"]["deb/trixie"]["stanzas"] == 2


# -- config / module contract --


def test_config_validation():
    with pytest.raises(ValueError):
        RepoSpec(
            name="x",
            base_url="http://insecure.test",
            suite="s",
            components=("main",),
            select=(".*",),
        )
    with pytest.raises(ValueError):
        RepoSpec(
            name="x", base_url=BASE, suite="s", components=("main",), select=("(",)
        )
    with pytest.raises(ValueError):
        RepoSpec(
            name="x", base_url=BASE, suite="../s", components=("main",), select=(".*",)
        )
    with pytest.raises(ValueError):
        AptConfig(repos=(), max_packages=-1)


@pytest.mark.parametrize("mod", [apt, pmc])
def test_module_contract(mod):
    assert mod.SOURCE == mod.__name__.rsplit(".", 1)[1]
    cfg = mod.DEFAULT_CONFIG
    assert cfg.max_packages is None
    assert cfg.repos and all(r.base_url.startswith("https://") for r in cfg.repos)
    import dataclasses

    assert dataclasses.is_dataclass(cfg)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.max_packages = 3  # type: ignore[misc]
    small = dataclasses.replace(cfg, max_packages=3)
    assert small.max_packages == 3


def test_default_selections():
    def sel(cfg, name, pkg):
        return any(r.selects(pkg) for r in cfg.repos if r.name == name)

    d = apt.DEFAULT_CONFIG
    for p in [
        "mono-runtime",
        "libmono-corlib4.5-cil",
        "wine64",
        "libwine",
        "shim-signed",
        "grub-efi-amd64-signed",
        "fwupd-amd64-signed",
    ]:
        assert sel(d, "debian", p), p
    for p in [
        "dotnet-sdk-8.0",
        "aspnetcore-runtime-8.0",
        "fwupd-signed",
        "netstandard-targeting-pack-2.1-8.0",
        "wine",
    ]:
        assert sel(d, "ubuntu", p), p
    for p in [
        "linux-image-6.8.0-31-generic",
        "dotnet-runtime-dbg-8.0",
        "dotnet-sdk-dbg-8.0",
        "aspnetcore-runtime-dbg-8.0",
        "dotnet-sdk-8.0-source-built-artifacts",
        "wine-dbg",
        "mono-doc",
        "bash",
        "libwine-dbgsym",
    ]:
        assert not sel(d, "debian", p) and not sel(d, "ubuntu", p), p
    m = pmc.DEFAULT_CONFIG
    for p in [
        "dotnet-sdk-9.0",
        "aspnetcore-runtime-8.0",
        "powershell",
        "netstandard-targeting-pack-2.1",
    ]:
        assert any(r.selects(p) for r in m.repos), p
    assert not any(r.selects("azure-cli") for r in m.repos)


def test_pmc_plan_uses_pmc_source():
    spec = RepoSpec(
        name="pmc-ubuntu-24.04",
        base_url=BASE,
        suite="noble",
        components=("main",),
        select=(r"dotnet-.*", r"powershell.*"),
    )
    pk = _packages(
        _stanza("powershell", "7.4.6-1.deb"), _stanza("powershell", "7.4.5-1.deb")
    )
    res = pmc.plan(
        FakeGetter(_repo(BASE, "noble", {"main": pk})), pmc.PmcConfig(repos=(spec,))
    )
    assert res.source == "pmc"
    assert [i.key for i in res.items] == [
        "pmc:pmc-ubuntu-24.04/noble/powershell_7.4.6-1.deb_amd64"
    ]
    assert "pmc/pmc-ubuntu-24.04/noble/InRelease" in res.anchors

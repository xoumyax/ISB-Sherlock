"""winget planner: commit -> manifest -> InstallerSha256, all offline.

Every catalogue here is a synthetic tar.gz built in memory with ``tarfile``; the
Getter is a dict of url -> bytes. No socket is ever opened.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import random
import tarfile
from dataclasses import replace

import pytest

from sherlock.collect.catalog import winget
from sherlock.collect.catalog.winget import (
    DEFAULT_CONFIG,
    SOURCE,
    WingetConfig,
    plan,
    version_key,
)
from sherlock.collect.items import CatalogResult

SHA = "0123456789abcdef0123456789abcdef01234567"
TOP = f"microsoft-winget-pkgs-{SHA[:7]}"
API = "https://api.github.com/repos/microsoft/winget-pkgs/commits/master"
TARBALL = f"https://codeload.github.com/microsoft/winget-pkgs/tar.gz/{SHA}"


def _hex(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


# -- fakes --


class FakeGetter:
    """url -> bytes; raises on an unknown url or an oversize body, like the real one."""

    def __init__(self, pages: dict[str, bytes]) -> None:
        self.pages = pages
        self.calls: list[tuple[str, int]] = []

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls.append((url, max_bytes))
        if url not in self.pages:
            raise OSError(f"404 {url}")
        body = self.pages[url]
        if len(body) > max_bytes:
            raise OSError(f"body over {max_bytes} bytes: {url}")
        return body


# -- manifest builders --


def _installer_yaml(
    ident: str,
    version: str,
    installers: list[dict],
    root: dict | None = None,
) -> bytes:
    lines = [
        f"PackageIdentifier: {ident}",
        f"PackageVersion: {version}",
    ]
    for k, v in (root or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("Installers:")
    for inst in installers:
        first = True
        for k, v in inst.items():
            lines.append(f"{'- ' if first else '  '}{k}: {v}")
            first = False
    lines += ["ManifestType: installer", "ManifestVersion: 1.6.0", ""]
    return "\n".join(lines).encode()


def _locale_yaml(
    ident: str,
    version: str,
    publisher: str,
    name: str = "App",
    licence: str = "MIT",
    default: bool = True,
) -> bytes:
    mtype = "defaultLocale" if default else "locale"
    return (
        f"PackageIdentifier: {ident}\n"
        f"PackageVersion: {version}\n"
        "PackageLocale: en-US\n"
        f"Publisher: {publisher}\n"
        f"PublisherUrl: https://{publisher.lower().replace(' ', '')}.example\n"
        f"PackageName: {name}\n"
        f"License: {licence}\n"
        "ShortDescription: test\n"
        f"ManifestType: {mtype}\n"
        "ManifestVersion: 1.6.0\n"
    ).encode()


def _version_yaml(ident: str, version: str) -> bytes:
    return (
        f"PackageIdentifier: {ident}\nPackageVersion: {version}\n"
        "DefaultLocale: en-US\nManifestType: version\nManifestVersion: 1.6.0\n"
    ).encode()


def _inst(
    arch: str = "x64",
    itype: str | None = "msi",
    url: str | None = None,
    sha: str | None = None,
    seed: str = "a",
) -> dict:
    d: dict = {"Architecture": arch}
    if itype is not None:
        d["InstallerType"] = itype
    d["InstallerUrl"] = url or f"https://dl.example.test/{seed}-{arch}.bin"
    if sha != "":
        d["InstallerSha256"] = sha or _hex(f"{seed}-{arch}-{itype}").upper()
    return d


def _pkg(
    ident: str,
    version: str,
    publisher: str,
    installers: list[dict] | None = None,
    root: dict | None = None,
    letter: str | None = None,
) -> dict[str, bytes]:
    """The three files of a multi-file manifest, keyed by repo path."""
    pub, _, name = ident.partition(".")
    letter = letter or pub[0].lower()
    base = f"manifests/{letter}/{pub}/{name}/{version}/{ident}"
    return {
        f"{base}.yaml": _version_yaml(ident, version),
        f"{base}.installer.yaml": _installer_yaml(
            ident, version, installers or [_inst(seed=ident + version)], root
        ),
        f"{base}.locale.en-US.yaml": _locale_yaml(ident, version, publisher),
    }


# -- tar builders --


def _tar(
    files: dict[str, bytes],
    top: str = TOP,
    extra: list[tarfile.TarInfo] | None = None,
    comment: str | None = SHA,
    shuffle_seed: int | None = None,
) -> bytes:
    """A GitHub-style tar.gz: pax global header with the commit, one top folder."""
    buf = io.BytesIO()
    pax = {"comment": comment} if comment is not None else {}
    names = sorted(files)
    if shuffle_seed is not None:
        random.Random(shuffle_seed).shuffle(names)
    with tarfile.open(
        fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers=pax
    ) as tf:
        d = tarfile.TarInfo(top + "/")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
        for name in names:
            data = files[name]
            ti = tarfile.TarInfo(f"{top}/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for ti in extra or []:
            tf.addfile(ti, io.BytesIO(b"x" * ti.size) if ti.isreg() else None)
    return buf.getvalue()


def _getter(tarball: bytes, sha: str = SHA) -> FakeGetter:
    return FakeGetter(
        {
            API: json.dumps({"sha": sha, "commit": {"message": "m"}}).encode(),
            f"https://codeload.github.com/microsoft/winget-pkgs/tar.gz/{sha}": tarball,
        }
    )


def _cfg(**kw) -> WingetConfig:
    return replace(DEFAULT_CONFIG, **kw)


def _by_pkg(res: CatalogResult) -> dict[str, object]:
    return {it.meta["package"]: it for it in res.items}


# -- contract --


def test_module_contract_and_defaults():
    assert SOURCE == "winget"
    assert DEFAULT_CONFIG.repo == "microsoft/winget-pkgs"
    assert DEFAULT_CONFIG.branch == "master"
    assert DEFAULT_CONFIG.commit is None
    assert DEFAULT_CONFIG.max_packages == 450
    assert DEFAULT_CONFIG.per_publisher_cap == 2
    assert DEFAULT_CONFIG.max_manifest_bytes == 1 << 20
    with pytest.raises(AttributeError):
        DEFAULT_CONFIG.max_packages = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "kw",
    [
        {"max_packages": -1},
        {"per_publisher_cap": 0},
        {"repo": "no-slash"},
        {"repo": "a/b/../c"},
        {"commit": "ABCDEF0123456789abcdef0123456789abcdef01"},
        {"commit": "abc"},
        {"allowed_installer_types": ("msi", "pwa")},
    ],
)
def test_bad_config_raises(kw):
    with pytest.raises(ValueError):
        WingetConfig(**kw)


# -- happy path --


def test_multi_file_manifest_planned_end_to_end():
    files = _pkg("Acme.Tool", "1.2.3", "Acme Corp")
    get = _getter(_tar(files))
    res = plan(get, _cfg())
    assert get.calls[0] == (API, get.calls[0][1])
    assert get.calls[1][0] == TARBALL
    assert get.calls[1][1] == DEFAULT_CONFIG.max_tarball_bytes
    (it,) = res.items
    assert it.source == "winget"
    assert it.key == "winget:Acme.Tool/1.2.3"
    assert it.url == "https://dl.example.test/Acme.Tool1.2.3-x64.bin"
    assert it.expected == {"sha256": _hex("Acme.Tool1.2.3-x64-msi")}
    assert it.size is None
    m = it.meta
    assert m["package"] == "Acme.Tool"
    assert m["version"] == "1.2.3"
    assert m["publisher"] == "Acme Corp"
    assert m["package_name"] == "App"
    assert m["licence"] == "MIT"
    assert m["installer_type"] == "msi"
    assert m["architecture"] == "x64"
    assert m["commit"] == SHA
    assert m["catalog_url"] == (
        f"https://github.com/microsoft/winget-pkgs/blob/{SHA}/"
        "manifests/a/Acme/Tool/1.2.3/Acme.Tool.installer.yaml"
    )
    assert m["source_date"] is None and m["date_kind"] is None
    assert m["vendor_evidence"] == {
        "publisher": "Acme Corp",
        "publisher_url": "https://acmecorp.example",
        "installer_host": "dl.example.test",
    }
    # JSON-able throughout
    json.dumps([i.to_dict() for i in res.items])
    json.dumps(res.summary())
    # anchors small, bytes, and never the tarball
    tb = get.pages[TARBALL]
    assert all(isinstance(v, bytes) for v in res.anchors.values())
    assert sum(len(v) for v in res.anchors.values()) < 4096
    anchor = json.loads(res.anchors["winget_commit.json"])
    assert anchor["commit"] == SHA
    assert anchor["tarball_sha256"] == hashlib.sha256(tb).hexdigest()
    assert anchor["tarball_bytes"] == len(tb)
    assert res.stats["tarball_sha256"] == hashlib.sha256(tb).hexdigest()
    assert res.stats["tarball_bytes"] == len(tb)
    assert res.stats["commit"] == SHA
    assert res.stats["selected"] == 1
    for k in ("members_seen", "manifests_parsed", "packages", "eligible"):
        assert k in res.stats


def test_singleton_manifest_parsed():
    body = (
        "PackageIdentifier: Solo.App\nPackageVersion: 2.0\nPackageLocale: en-US\n"
        "Publisher: Solo Ltd\nPackageName: Solo\nLicense: Apache-2.0\n"
        "ShortDescription: s\nInstallers:\n- Architecture: x86\n"
        "  InstallerType: nullsoft\n  InstallerUrl: https://solo.example/s.exe\n"
        f"  InstallerSha256: {_hex('solo')}\n"
        "ManifestType: singleton\nManifestVersion: 1.0.0\n"
    ).encode()
    res = plan(_getter(_tar({"manifests/s/Solo/App/2.0/Solo.App.yaml": body})), _cfg())
    (it,) = res.items
    assert it.key == "winget:Solo.App/2.0"
    assert it.meta["publisher"] == "Solo Ltd"
    assert it.meta["licence"] == "Apache-2.0"
    assert it.meta["installer_type"] == "nullsoft"
    assert it.meta["catalog_url"].endswith("manifests/s/Solo/App/2.0/Solo.App.yaml")


def test_pinned_commit_skips_api_call():
    get = _getter(_tar(_pkg("Acme.Tool", "1.0", "Acme")))
    res = plan(get, _cfg(commit=SHA))
    assert [u for u, _ in get.calls] == [TARBALL]
    assert len(res.items) == 1


def test_root_level_installer_type_and_release_date_inherited():
    files = _pkg(
        "Acme.Tool",
        "1.0",
        "Acme",
        installers=[_inst(itype=None, seed="r")],
        root={"InstallerType": "wix", "Scope": "machine", "ReleaseDate": "2024-03-05"},
    )
    (it,) = plan(_getter(_tar(files)), _cfg()).items
    assert it.meta["installer_type"] == "wix"
    assert it.meta["scope"] == "machine"
    assert it.meta["source_date"] == "2024-03-05"
    assert it.meta["date_kind"] == "winget_release_date"


def test_installer_level_overrides_root():
    inst = _inst(itype="msix", seed="o")
    inst["ReleaseDate"] = "2025-01-02"
    files = _pkg(
        "Acme.Tool",
        "1.0",
        "Acme",
        installers=[inst],
        root={"InstallerType": "exe", "ReleaseDate": "2020-01-01"},
    )
    (it,) = plan(_getter(_tar(files)), _cfg()).items
    assert it.meta["installer_type"] == "msix"
    assert it.meta["source_date"] == "2025-01-02"


# -- versions --


def test_version_key_is_natural_and_total():
    assert version_key("1.10") > version_key("1.9")
    assert version_key("10.0") > version_key("9.99.99")
    assert version_key("2.0.1") > version_key("2.0")
    # digit vs letter in the same slot compares without TypeError
    sorted(["1.0.a", "1.0.1", "v2", "2", "1.0-beta", ""], key=version_key)


def test_highest_version_kept_and_folder_name_is_the_version():
    files = {}
    for v in ("1.9", "1.10", "1.2"):
        files |= _pkg("Acme.Tool", v, "Acme")
    res = plan(_getter(_tar(files)), _cfg())
    (it,) = res.items
    # unquoted 1.10 is the float 1.1 to safe_load; the folder name keeps it exact
    assert it.key == "winget:Acme.Tool/1.10"
    assert it.meta["version"] == "1.10"
    assert res.stats["version_mismatch"] >= 1


def test_broken_highest_version_does_not_fall_back():
    files = _pkg("Acme.Tool", "1.0", "Acme")
    files |= _pkg("Acme.Tool", "2.0", "Acme", installers=[_inst(arch="arm64")])
    res = plan(_getter(_tar(files)), _cfg())
    assert res.items == ()
    assert res.dropped.get("no_supported_architecture") == 1


# -- installer choice --


def test_x64_preferred_over_x86_and_arm64_skipped():
    files = _pkg(
        "Acme.Tool",
        "1.0",
        "Acme",
        installers=[
            _inst(arch="arm64", seed="p"),
            _inst(arch="x86", seed="p"),
            _inst(arch="x64", seed="p"),
        ],
    )
    files |= _pkg("Beta.Only", "1.0", "Beta", installers=[_inst(arch="arm64")])
    files |= _pkg("Gam.Mix", "1.0", "Gam", installers=[_inst(arch="x86", seed="g")])
    res = plan(_getter(_tar(files)), _cfg())
    got = _by_pkg(res)
    assert got["Acme.Tool"].meta["architecture"] == "x64"
    assert got["Gam.Mix"].meta["architecture"] == "x86"
    assert "Beta.Only" not in got
    assert res.dropped["no_supported_architecture"] == 1
    assert res.stats["packages"] == 3


def test_installer_type_preference_and_exclusions():
    files = _pkg(
        "Acme.Tool",
        "1.0",
        "Acme",
        installers=[_inst(itype="exe", seed="t"), _inst(itype="msi", seed="t")],
    )
    files |= _pkg("Pwa.App", "1.0", "Pwa", installers=[_inst(itype="pwa")])
    files |= _pkg("Font.Pack", "1.0", "Font", installers=[_inst(itype="font")])
    res = plan(_getter(_tar(files)), _cfg())
    got = _by_pkg(res)
    assert got["Acme.Tool"].meta["installer_type"] == "msi"
    assert set(got) == {"Acme.Tool"}
    assert res.dropped["installer_type_excluded"] == 2


def test_http_url_dropped_but_https_alternative_used():
    files = _pkg(
        "Http.Only",
        "1.0",
        "H",
        installers=[_inst(url="http://insecure.example/x.msi")],
    )
    files |= _pkg(
        "Http.Mixed",
        "1.0",
        "M",
        installers=[
            _inst(arch="x64", url="http://insecure.example/y.msi"),
            _inst(arch="x86", seed="mixed"),
        ],
    )
    res = plan(_getter(_tar(files)), _cfg())
    got = _by_pkg(res)
    assert "Http.Only" not in got
    assert got["Http.Mixed"].meta["architecture"] == "x86"
    assert res.dropped["not_https"] == 1


@pytest.mark.parametrize("sha", ["", "abc123", "zz" * 32, "ab" * 33])
def test_missing_or_bad_sha256_dropped(sha):
    files = _pkg("Bad.Sha", "1.0", "B", installers=[_inst(sha=sha)])
    res = plan(_getter(_tar(files)), _cfg())
    assert res.items == ()
    assert res.dropped["no_sha256"] == 1


def test_sha256_lowercased():
    files = _pkg("Up.Case", "1.0", "U", installers=[_inst(sha="AB" * 32)])
    (it,) = plan(_getter(_tar(files)), _cfg()).items
    assert it.expected == {"sha256": "ab" * 32}


def test_duplicate_installer_sha_kept_once():
    same = "cd" * 32
    files = _pkg("Aaa.One", "1.0", "P1", installers=[_inst(sha=same, seed="1")])
    files |= _pkg("Bbb.Two", "1.0", "P2", installers=[_inst(sha=same, seed="2")])
    res = plan(_getter(_tar(files)), _cfg())
    assert [i.meta["package"] for i in res.items] == ["Aaa.One"]
    assert res.dropped["duplicate_installer"] == 1


def test_missing_default_locale_dropped():
    files = _pkg("No.Locale", "1.0", "N")
    loc = next(k for k in files if ".locale." in k)
    files[loc] = _locale_yaml("No.Locale", "1.0", "N", default=False)
    res = plan(_getter(_tar(files)), _cfg())
    assert res.items == ()
    assert res.dropped["no_default_locale"] == 1


# -- selection --


def _many(n_pub: int, per_pub: int) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for p in range(n_pub):
        for k in range(per_pub):
            files |= _pkg(f"Pub{p:03d}.App{k}", "1.0", f"Publisher {p:03d}")
    return files


def test_per_publisher_cap():
    files = _many(3, 5)
    # same publisher spelled differently still counts once
    files |= _pkg("Zed.App", "1.0", "  PUBLISHER 000 ")
    res = plan(_getter(_tar(files)), _cfg(per_publisher_cap=2))
    pubs: dict[str, int] = {}
    for it in res.items:
        p = it.meta["publisher"].casefold().strip()
        pubs[p] = pubs.get(p, 0) + 1
    assert max(pubs.values()) == 2
    assert len(res.items) == 6
    assert res.dropped["publisher_cap"] == 10
    assert res.stats["publishers"] == 3


def test_seeded_selection_reproducible_and_capped():
    tb = _tar(_many(30, 1))
    a = plan(_getter(tb), _cfg(max_packages=7, seed=0))
    b = plan(_getter(tb), _cfg(max_packages=7, seed=0))
    c = plan(_getter(tb), _cfg(max_packages=7, seed=1))
    assert len(a.items) == 7
    assert [i.to_dict() for i in a.items] == [i.to_dict() for i in b.items]
    assert [i.key for i in a.items] != [i.key for i in c.items]
    assert a.stats["eligible"] == 30
    assert a.stats["selected"] == 7
    # fewer eligible than the cap: take all, no error
    assert len(plan(_getter(tb), _cfg(max_packages=450)).items) == 30
    assert plan(_getter(tb), _cfg(max_packages=0)).items == ()


def test_plan_independent_of_archive_order():
    files = _many(6, 3)
    for v in ("0.9", "1.10", "1.9"):
        files |= _pkg("Ver.Sion", v, "Versions Inc")
    a = plan(_getter(_tar(files, shuffle_seed=1)), _cfg(max_packages=5))
    b = plan(_getter(_tar(files, shuffle_seed=2)), _cfg(max_packages=5))
    assert [i.to_dict() for i in a.items] == [i.to_dict() for i in b.items]


# -- untrusted catalogue --


def _bad_members() -> list[tarfile.TarInfo]:
    out = []
    for name, kind in [
        (f"{TOP}/manifests/e/Evil/Up/1.0/../../../../../evil.yaml", tarfile.REGTYPE),
        ("/manifests/e/Evil/Abs/1.0/Evil.Abs.installer.yaml", tarfile.REGTYPE),
        ("other-top/manifests/e/Evil/Top/1.0/Evil.Top.installer.yaml", tarfile.REGTYPE),
        (f"{TOP}/manifests/e/Evil/Sym/1.0/Evil.Sym.installer.yaml", tarfile.SYMTYPE),
        (f"{TOP}/manifests/e/Evil/Hard/1.0/Evil.Hard.installer.yaml", tarfile.LNKTYPE),
        (f"{TOP}/manifests/e/Evil/Dev/1.0/Evil.Dev.installer.yaml", tarfile.CHRTYPE),
        (f"{TOP}/manifests/e/Evil/Fifo/1.0/Evil.Fifo.installer.yaml", tarfile.FIFOTYPE),
    ]:
        ti = tarfile.TarInfo(name)
        ti.type = kind
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            ti.linkname = "/etc/passwd"
        ti.size = 4 if kind == tarfile.REGTYPE else 0
        out.append(ti)
    return out


def test_unsafe_members_ignored_and_nothing_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def boom(*a, **k):
        raise AssertionError("extraction attempted")

    monkeypatch.setattr(tarfile.TarFile, "extract", boom)
    monkeypatch.setattr(tarfile.TarFile, "extractall", boom)
    files = _pkg("Acme.Tool", "1.0", "Acme")
    files["README.md"] = b"not a manifest"
    files["manifests/a/Acme/Tool/1.0/notes.txt"] = b"not yaml"
    res = plan(_getter(_tar(files, extra=_bad_members())), _cfg())
    assert [i.meta["package"] for i in res.items] == ["Acme.Tool"]
    assert res.dropped["unsafe_member"] >= 5
    assert not any(k.startswith("Evil") for k in _by_pkg(res))
    assert os.listdir(tmp_path) == []


def test_oversize_member_skipped():
    files = _pkg("Acme.Tool", "1.0", "Acme")
    big = _pkg("Big.One", "1.0", "Big")
    k = next(p for p in big if p.endswith(".installer.yaml"))
    big[k] = big[k] + b"#" * 5000
    files |= big
    res = plan(_getter(_tar(files)), _cfg(max_manifest_bytes=4096))
    assert set(_by_pkg(res)) == {"Acme.Tool"}
    assert res.dropped["manifest_too_large"] == 1


def test_python_yaml_tags_rejected_not_executed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    files = _pkg("Acme.Tool", "1.0", "Acme")
    evil = _pkg("Evil.Tag", "1.0", "Evil")
    k = next(p for p in evil if p.endswith(".installer.yaml"))
    evil[k] = (
        b"PackageIdentifier: !!python/object/apply:os.system ['touch pwned']\n"
        b"PackageVersion: 1.0\nInstallers: []\nManifestType: installer\n"
    )
    files |= evil
    res = plan(_getter(_tar(files)), _cfg())
    assert set(_by_pkg(res)) == {"Acme.Tool"}
    assert res.dropped["yaml_error"] == 1
    assert os.listdir(tmp_path) == []


def test_garbage_yaml_tolerated():
    files = _pkg("Acme.Tool", "1.0", "Acme")
    junk = _pkg("Junk.App", "1.0", "Junk")
    k = next(p for p in junk if p.endswith(".installer.yaml"))
    junk[k] = b"PackageIdentifier: [unclosed\n\t: :"
    files |= junk
    files |= {"manifests/l/List/App/1.0/List.App.installer.yaml": b"- just\n- a list\n"}
    files |= {"manifests/d/Date/App/1.0/Date.App.installer.yaml": b"x: 2024-13-45\n"}
    res = plan(_getter(_tar(files)), _cfg())
    assert set(_by_pkg(res)) == {"Acme.Tool"}
    assert res.dropped["yaml_error"] >= 1


def test_member_limit_raises():
    files = _many(5, 1)
    with pytest.raises(ValueError, match="max_members"):
        plan(_getter(_tar(files)), _cfg(max_members=4))


def test_expanded_bytes_limit_raises():
    files = _many(5, 1)
    with pytest.raises(ValueError, match="max_expanded_bytes"):
        plan(_getter(_tar(files)), _cfg(max_expanded_bytes=1000))


@pytest.mark.parametrize("order", [1, 2, 3])
def test_kept_bytes_accounting_across_many_versions(order):
    files: dict[str, bytes] = {}
    for v in range(20):
        files |= _pkg("Acme.Tool", f"1.{v}", "Acme")
    one = sum(len(b) for k, b in files.items() if "/1.19/" in k)
    res = plan(_getter(_tar(files, shuffle_seed=order)), _cfg(max_kept_bytes=one + 64))
    assert [i.key for i in res.items] == ["winget:Acme.Tool/1.19"]


# -- chain checks --


def test_truncated_gzip_raises():
    tb = _tar(_pkg("Acme.Tool", "1.0", "Acme"))
    with pytest.raises(ValueError, match="tarball"):
        plan(_getter(tb[:-20]), _cfg())


def test_missing_pax_comment_still_plans():
    res = plan(_getter(_tar(_pkg("Acme.Tool", "1.0", "A"), comment=None)), _cfg())
    assert len(res.items) == 1
    assert res.stats["tar_pax_commit_matches"] is False


@pytest.mark.parametrize(
    "bad", ["ABCDEF0123456789abcdef0123456789abcdef01", "abc", "", None, 12]
)
def test_api_commit_sha_validated(bad):
    get = FakeGetter({API: json.dumps({"sha": bad}).encode()})
    with pytest.raises(ValueError, match="sha"):
        plan(get, _cfg())
    assert len(get.calls) == 1


def test_api_not_json_raises():
    get = FakeGetter({API: b"<html>rate limited</html>"})
    with pytest.raises(ValueError):
        plan(get, _cfg())


def test_tarball_commit_must_match_pax_comment():
    other = "f" * 40
    with pytest.raises(ValueError, match="commit"):
        plan(_getter(_tar(_pkg("Acme.Tool", "1.0", "A"), comment=other)), _cfg())


def test_tarball_over_limit_surfaces_clearly():
    tb = _tar(_pkg("Acme.Tool", "1.0", "Acme"))
    with pytest.raises(OSError, match="over"):
        plan(_getter(tb), _cfg(max_tarball_bytes=len(tb) - 1))


def test_getter_ignoring_limit_still_caught():
    tb = _tar(_pkg("Acme.Tool", "1.0", "Acme"))

    def lax(url: str, max_bytes: int) -> bytes:
        return _getter(tb).pages[url]

    with pytest.raises(ValueError, match="max_tarball_bytes"):
        plan(lax, _cfg(max_tarball_bytes=len(tb) - 1))


def test_not_a_gzip_tar_raises():
    with pytest.raises(ValueError, match="tarball"):
        plan(_getter(gzip.compress(b"not a tar" * 100)), _cfg())


def test_module_never_imports_network_or_pickle():
    src = open(winget.__file__, encoding="utf-8").read()
    for bad in ("import socket", "import requests", "urlopen", "pickle", "extractall"):
        assert bad not in src
    assert "yaml.load(" not in src and "yaml.unsafe" not in src


def test_non_ascii_installer_url_dropped():
    files = _pkg(
        "Uni.Code",
        "1.0",
        "U",
        installers=[_inst(url="https://dl.example/über/x.msi")],
    )
    res = plan(_getter(_tar(files)), _cfg())
    assert "Uni.Code" not in _by_pkg(res)
    assert res.dropped["non_ascii_url"] == 1

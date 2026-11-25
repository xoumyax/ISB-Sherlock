"""End-to-end CLI runs against a MockTransport serving a synthetic NuGet."""

from __future__ import annotations

import dataclasses
import json
import logging
import re

import pytest

from sherlock.cli import collect as cli
from sherlock.collect.http import MockResponse, MockTransport

_ABS = re.compile(r"(?<![\w.:/%-])/(home|tmp|scratch|oak|users|var|mnt)/")


def _transport(nuget_fake, **kw):
    cat, pay = nuget_fake(**kw)
    routes = {u: MockResponse(200, b) for u, b in {**cat, **pay}.items()}
    return MockTransport(routes), cat, pay


def _env(tmp_path, data=None):
    data = data or tmp_path / "data"
    data.mkdir(exist_ok=True)
    return {
        "ISB_DATA": str(data),
        "ISB_WORK": str(tmp_path / "work"),
        "ISB_SCRATCH": str(tmp_path / "scratch"),
    }


def _main(argv, env, t, tmp_path):
    return cli.main(
        argv,
        transport=t,
        env=env,
        config_path=tmp_path / "none.yaml",
        sleep=lambda s: None,
        disk_free=lambda p: 10**15,
    )


def _runs(work):
    return sorted((work / "runs" / "collect" / "nuget").glob("*/run.json"))


def test_cli_run_end_to_end(nuget_fake, tmp_path, caplog):
    t, cat, pay = _transport(nuget_fake)
    env = _env(tmp_path)
    caplog.set_level(logging.DEBUG)
    rc = _main(["run", "--source", "nuget", "--budget-gib", "1"], env, t, tmp_path)
    assert rc == 0
    work = tmp_path / "work"
    src = work / "intake" / "nuget"
    plans = [p for p in src.iterdir() if p.name.startswith("nuget-")]
    assert len(plans) == 1
    pdir = plans[0]
    assert (pdir / "plan.json").is_file()
    assert (pdir / "checkpoint.json").is_file()
    assert len(list((pdir / "receipts").iterdir())) == 3
    stored = [p for p in (src / "store").rglob("*") if p.is_file()]
    assert len(stored) == 3
    (run_json,) = _runs(work)
    rec = json.loads(run_json.read_text())
    assert rec["status"] == "ok" and rec["experiment"] == "collect"
    assert rec["arm"] == "nuget"
    assert rec["config"]["plan_id"] == pdir.name
    assert len(rec["config"]["plan_sha256"]) == 64
    assert rec["config"]["budget_bytes"] == 1 << 30
    assert rec["stats"]["stopped"] == "complete" and rec["stats"]["n_ok"] == 3
    # no header ever logged
    assert "User-Agent" not in caplog.text

    # resume: second run replays, no new payload requests, new run.json
    n_calls = len(t.calls)
    rc = _main(["run", "--source", "nuget", "--budget-gib", "1"], env, t, tmp_path)
    assert rc == 0
    payload_calls = [u for _, u in t.calls[n_calls:] if u.endswith(".nupkg")]
    assert payload_calls == []
    assert len(_runs(work)) == 2
    rec2 = json.loads(_runs(work)[-1].read_text())
    stats = [json.loads(p.read_text())["stats"] for p in _runs(work)]
    assert sorted(s["n_replayed"] for s in stats) == [0, 3]
    assert rec2["config"]["plan_id"] == pdir.name

    # verify (read-only) finds the store intact, then a tamper
    assert (
        _main(["verify", "--source", "nuget", "--plan", pdir.name], env, t, tmp_path)
        == 0
    )
    victim = stored[0]
    victim.chmod(0o640)
    victim.write_bytes(b"x")
    assert (
        _main(["verify", "--source", "nuget", "--plan", pdir.name], env, t, tmp_path)
        != 0
    )


def test_no_absolute_path_in_outputs_or_run_json(nuget_fake, tmp_path):
    t, cat, pay = _transport(nuget_fake)
    # make one payload fail mid-stream so failure receipts are written too
    url = next(iter(pay))
    t.routes[url] = MockResponse(200, pay[url], chunk=10, fail_after=20)
    env = _env(tmp_path)
    _main(["run", "--source", "nuget", "--budget-gib", "1"], env, t, tmp_path)
    work = tmp_path / "work"
    texts = [p for p in work.rglob("*") if p.is_file() and p.suffix == ".json"]
    assert texts
    for p in texts:
        body = p.read_text()
        assert str(tmp_path) not in body, p.name
        assert not _ABS.search(body), p.name


def test_never_writes_under_dataset_root(nuget_fake, tmp_path):
    t, _, _ = _transport(nuget_fake)
    data = tmp_path / "data"
    data.mkdir()
    env = _env(tmp_path, data)
    env["ISB_WORK"] = str(data / "work")
    before = sorted(data.rglob("*"))
    rc = _main(["run", "--source", "nuget", "--budget-gib", "1"], env, t, tmp_path)
    assert rc != 0
    assert sorted(data.rglob("*")) == before
    assert t.calls == []


def test_plan_then_pull_subcommands_and_plan_limit(nuget_fake, tmp_path):
    t, _, _ = _transport(nuget_fake)
    env = _env(tmp_path)
    assert (
        _main(["plan", "--source", "nuget", "--plan-limit", "2"], env, t, tmp_path) == 0
    )
    src = tmp_path / "work" / "intake" / "nuget"
    (pdir,) = [p for p in src.iterdir() if p.name.startswith("nuget-")]
    assert len(json.loads((pdir / "plan.json").read_text())["items"]) == 2
    assert not any(u.endswith(".nupkg") for _, u in t.calls)
    assert (
        _main(
            ["pull", "--plan", pdir.name, "--budget-gib", "1", "--max-items", "1"],
            env,
            t,
            tmp_path,
        )
        == 0
    )
    assert len(list((pdir / "receipts").iterdir())) == 1


def test_catalogue_off_allowlist_host_fails_run(nuget_fake, tmp_path):
    t, cat, _ = _transport(nuget_fake)
    idx = json.loads(cat["https://api.nuget.org/v3/index.json"])
    idx["resources"][0]["@id"] = "https://search.other.test/query"
    t.routes["https://api.nuget.org/v3/index.json"] = MockResponse(
        200, json.dumps(idx).encode()
    )
    env = _env(tmp_path)
    rc = _main(["run", "--source", "nuget", "--budget-gib", "1"], env, t, tmp_path)
    assert rc != 0
    (run_json,) = _runs(tmp_path / "work")
    rec = json.loads(run_json.read_text())
    assert rec["status"] == "failed" and "allowlist" in rec["error"]


def test_unknown_source_refused(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["run", "--source", "nope", "--budget-gib", "1"])


def test_registry_and_hosts_cover_all_sources():
    assert set(cli.REGISTRY) == {"nuget", "apt", "pmc", "winget"}
    assert set(cli.CATALOG_HOSTS) == set(cli.REGISTRY)


def test_seed_passed_to_catalogue_config_with_seed_field(monkeypatch, tmp_path):
    import dataclasses
    import types

    from sherlock.collect.items import CatalogResult, PlanItem

    @dataclasses.dataclass(frozen=True)
    class Cfg:
        seed: int = 0
        max_packages: int | None = None

    seen = {}

    def plan(get, cfg):
        seen["cfg"] = cfg
        it = PlanItem(
            source="nuget",
            key="nuget:a/1",
            url="https://api.nuget.org/a",
            expected={"sha512": "ab" * 64},
            size=1,
        )
        return CatalogResult(source="nuget", items=(it,))

    mod = types.SimpleNamespace(SOURCE="nuget", DEFAULT_CONFIG=Cfg(), plan=plan)
    real = cli.importlib.import_module
    monkeypatch.setattr(
        cli.importlib,
        "import_module",
        lambda name: mod if name == cli.REGISTRY["nuget"] else real(name),
    )
    env = _env(tmp_path)
    rc = _main(
        ["plan", "--source", "nuget", "--seed", "42"], env, MockTransport({}), tmp_path
    )
    assert rc == 0 and seen["cfg"].seed == 42


def test_verify_unknown_plan_fails(tmp_path):
    env = _env(tmp_path)
    rc = _main(
        ["verify", "--source", "nuget", "--plan", "nuget-20261125-abcdefabcdef"],
        env,
        MockTransport({}),
        tmp_path,
    )
    assert rc != 0


@pytest.mark.parametrize("source", sorted(cli.REGISTRY))
def test_planner_modules_honour_cli_contract(source):
    import dataclasses
    import importlib

    mod = importlib.import_module(cli.REGISTRY[source])
    assert mod.SOURCE == source
    assert callable(mod.plan)
    dataclasses.replace(mod.DEFAULT_CONFIG, max_packages=1)


def test_source_lock_held_exits_3_without_touching_state(nuget_fake, tmp_path):
    import fcntl

    t, _, _ = _transport(nuget_fake)
    env = _env(tmp_path)
    src = tmp_path / "work" / "intake" / "nuget"
    (src / "tmp").mkdir(parents=True)
    stale = src / "tmp" / "x.part"
    stale.write_bytes(b"in flight")
    ledger = src / "ledger.json"
    ledger.write_text('{"budget_bytes": 1, "spent": 0, "open": {"k": 5}}')
    with open(src / ".lock", "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = _main(["run", "--source", "nuget", "--budget-gib", "1"], env, t, tmp_path)
    assert rc == 3
    assert stale.read_bytes() == b"in flight"
    assert json.loads(ledger.read_text())["open"] == {"k": 5}
    assert t.calls == []
    (run_json,) = _runs(tmp_path / "work")
    rec = json.loads(run_json.read_text())
    assert rec["status"] == "failed" and "lock" in rec["error"]


def test_other_failures_are_not_exit_3(nuget_fake, tmp_path):
    t, cat, _ = _transport(nuget_fake)
    t.routes.pop("https://api.nuget.org/v3/index.json")
    rc = _main(
        ["run", "--source", "nuget", "--budget-gib", "1"], _env(tmp_path), t, tmp_path
    )
    assert rc not in (0, 3)


def test_plan_drops_and_per_repo_surface_in_run_json(monkeypatch, tmp_path):
    import types

    from sherlock.collect.items import CatalogResult, PlanItem

    @dataclasses.dataclass(frozen=True)
    class Cfg:
        max_packages: int | None = None

    def plan(get, cfg):
        it = PlanItem(
            source="apt",
            key="apt:a/1",
            url="https://deb.debian.org/a",
            expected={"sha256": "ab" * 32},
            size=1,
        )
        return CatalogResult(
            source="apt",
            items=(it,),
            dropped={"repo_failed:debian/trixie": 1, "other": 2},
            stats={
                "per_repo": {
                    "debian/trixie": {
                        "selected": 0,
                        "indexes": 0,
                        "error": "InRelease missing",
                    }
                }
            },
        )

    mod = types.SimpleNamespace(SOURCE="apt", DEFAULT_CONFIG=Cfg(), plan=plan)
    real = cli.importlib.import_module
    monkeypatch.setattr(
        cli.importlib,
        "import_module",
        lambda name: mod if name == cli.REGISTRY["apt"] else real(name),
    )
    rc = _main(["plan", "--source", "apt"], _env(tmp_path), MockTransport({}), tmp_path)
    assert rc == 0
    (rj,) = sorted((tmp_path / "work" / "runs" / "collect" / "apt").glob("*/run.json"))
    st = json.loads(rj.read_text())["stats"]
    assert st["plan_dropped"]["repo_failed:debian/trixie"] == 1
    assert st["plan_per_repo"]["debian/trixie"]["error"] == "InRelease missing"


def test_catalogue_bytes_in_run_stats(nuget_fake, tmp_path):
    t, _, _ = _transport(nuget_fake)
    _main(
        ["run", "--source", "nuget", "--budget-gib", "1"], _env(tmp_path), t, tmp_path
    )
    (rj,) = _runs(tmp_path / "work")
    st = json.loads(rj.read_text())["stats"]
    assert st["catalog_bytes_by_host"]["api.nuget.org"] > 0


def test_error_before_main_try_is_scrubbed(tmp_path, caplog):
    env = _env(tmp_path)
    env["ISB_DATA"] = str(tmp_path / "missing-data-dir")
    rc = _main(
        ["run", "--source", "nuget", "--budget-gib", "1"],
        env,
        MockTransport({}),
        tmp_path,
    )
    assert rc not in (0, 3)
    assert str(tmp_path) not in caplog.text

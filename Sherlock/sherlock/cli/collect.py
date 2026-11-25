"""``python -m sherlock.cli.collect``: plan, pull, run and verify one goodware source.

COLLECT §6. Fetch-only (C20): nothing here unpacks or parses payload bytes.

* ``run --source S --budget-gib N [--plan-limit N] [--max-items N] [--seed S]``:
  plan then pull in one invocation (the sbatch shape). If a plan of this source
  with the same planner parameters already exists, the newest one is reused, so
  a requeued job resumes instead of re-reading the catalogue (``--replan`` forces
  a fresh plan; payloads still replay from the store across plans).
* ``plan --source S``: catalogue only; writes the frozen plan.
* ``pull --plan <plan_id> --budget-gib N``: pull an existing plan.
* ``verify --source S --plan <plan_id>``: read-only re-hash of every stored file
  named by an ok receipt.

One collect process per source: ``intake/<source>/.lock`` (flock, non-blocking)
is held for the whole invocation; if another run holds it the CLI exits 3 without
touching ``.part`` files or the ledger. Planner drops (including every
``repo_failed:*``) and apt/pmc ``per_repo`` stats go into run.json stats
(``plan_dropped``, ``plan_per_repo``) and are logged at WARNING.

Every invocation writes ``ISB_WORK/runs/collect/<source>/<run_id>/run.json``.
Status: ``ok`` for complete, budget, projected-over-budget and max-items stops
(C16); ``failed`` for a tripped host set, the disk floor, a checkpoint sample with
no verified item, a full local disk, an empty plan (never written, never
reused), a verify mismatch or missing plan, or any exception. Exit codes: 0 ok,
1 failed run, 2 setup error (roots, dataset-root guard), 3 source lock held (the
sbatch must not retry).

Logging (stderr) lives only here. Request headers are never logged, and error
text is scrubbed of local absolute paths before it reaches run.json.
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import importlib
import json
import logging
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import IO, Any

from sherlock.collect.http import Fetcher, HttpConfig, Transport, UrllibTransport
from sherlock.collect.ledger import Ledger
from sherlock.collect.plan import Plan, load_plan, make_plan, write_plan
from sherlock.collect.pull import FAILED_STOPS, PullConfig, pull
from sherlock.collect.store import Store, StoreConfig
from sherlock.core.records import RunRecord
from sherlock.data.roots import Roots, resolve_roots

__all__ = ["CATALOG_HOSTS", "REGISTRY", "main"]

log = logging.getLogger("sherlock.cli.collect")

#: source -> planner module (imported lazily; each has SOURCE, DEFAULT_CONFIG, plan).
REGISTRY: Mapping[str, str] = {
    "nuget": "sherlock.collect.catalog.nuget",
    "apt": "sherlock.collect.catalog.apt",
    "pmc": "sherlock.collect.catalog.pmc",
    "winget": "sherlock.collect.catalog.winget",
}

#: Catalogue hosts the planners' Getter may reach, per source. Payload downloads
#: may redirect elsewhere over https (checksum-anchored).
CATALOG_HOSTS: Mapping[str, frozenset[str]] = {
    # SearchQueryService lives on the azuresearch hosts, not api.nuget.org.
    "nuget": frozenset(
        {"api.nuget.org", "azuresearch-usnc.nuget.org", "azuresearch-ussc.nuget.org"}
    ),
    "apt": frozenset({"deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com"}),
    "pmc": frozenset({"packages.microsoft.com"}),
    "winget": frozenset({"api.github.com", "codeload.github.com"}),
}

GiB = 1 << 30
#: Exit code when another collect run holds the source lock: the sbatch wrapper
#: treats it as "do not retry". Other failures exit 1 (run) or 2 (setup).
EXIT_LOCKED = 3
_ABS = re.compile(r"(?<![\w.:/%-])/[^\s'\"]+")


# -- helpers ------------------------------------------------------------------


def _scrub(text: str, roots: Roots | None) -> str:
    if roots is not None:
        for name in ("dataset", "work", "scratch", "zips"):
            p = getattr(roots, name)
            if p is not None:
                text = text.replace(str(p), f"<{name}>")
    return _ABS.sub("<path>", text)[:2000]


def _check_roots(roots: Roots) -> Path:
    intake = (roots.work / "intake").resolve()
    runs = (roots.work / "runs").resolve()
    data = roots.dataset.resolve()
    for p in (intake, runs):
        if p == data or p.is_relative_to(data):
            raise ValueError(
                "ISB_WORK resolves under the dataset root; collect never writes "
                "there. Point ISB_WORK (or work_root) elsewhere."
            )
    return roots.work / "intake"


def _event_logger(kind: str, data: Mapping[str, Any]) -> None:
    if kind == "item":
        level = logging.DEBUG if data.get("status") == "ok" else logging.INFO
        log.log(
            level,
            "item %s %s %s",
            data.get("key"),
            data.get("status"),
            data.get("error") or "",
        )
    else:
        safe = {k: v for k, v in data.items() if k != "headers"}
        log.info("%s %s", kind, json.dumps(safe, sort_keys=True, default=str))


def _find_plan(intake: Path, source: str, params: Mapping[str, Any]) -> str | None:
    best: tuple[str, str] | None = None
    for pj in (intake / source).glob(f"{source}-*/plan.json"):
        try:
            body = json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if body.get("params") != dict(params) or not body.get("items"):
            continue
        cand = (str(body.get("created_at", "")), pj.parent.name)
        if best is None or cand > best:
            best = cand
    return best[1] if best else None


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m sherlock.cli.collect")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser, *, source_required: bool = True) -> None:
        p.add_argument("--source", choices=sorted(REGISTRY), required=source_required)
        p.add_argument("-v", "--verbose", action="store_true")

    for name in ("run", "plan"):
        p = sub.add_parser(name)
        common(p)
        p.add_argument("--plan-limit", type=int, default=None)
        p.add_argument("--seed", type=int, default=None)
        if name == "run":
            p.add_argument("--budget-gib", type=float, required=True)
            p.add_argument("--max-items", type=int, default=None)
            p.add_argument("--min-free-gib", type=float, default=50.0)
            p.add_argument("--replan", action="store_true")
    p = sub.add_parser("pull")
    common(p, source_required=False)
    p.add_argument("--plan", required=True)
    p.add_argument("--budget-gib", type=float, required=True)
    p.add_argument("--max-items", type=int, default=None)
    p.add_argument("--min-free-gib", type=float, default=50.0)
    p = sub.add_parser("verify")
    common(p)
    p.add_argument("--plan", required=True)
    return ap


# -- main ---------------------------------------------------------------------


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: Transport | None = None,
    env: Mapping[str, str] | None = None,
    config_path: Path | None = None,
    sleep: Callable[[float], None] | None = None,
    clock: Callable[[], float] | None = None,
    disk_free: Callable[[Path], int] | None = None,
) -> int:
    args = _parser().parse_args(argv)
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            stream=sys.stderr,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    if args.source is None:  # pull: derive from the plan id
        args.source = str(args.plan).split("-", 1)[0]
        if args.source not in REGISTRY:
            log.error("cannot tell the source from plan id %r", args.plan)
            return 2
    source = args.source

    roots: Roots | None = None
    try:
        roots = resolve_roots(env, config_path)
        intake = _check_roots(roots)
    except Exception as exc:  # noqa: BLE001 - scrubbed, never a raw traceback
        log.error(
            "collect setup failed: %s", _scrub(f"{type(exc).__name__}: {exc}", roots)
        )
        return 2

    config: dict[str, Any] = {"command": args.cmd, "source": source}
    for k in ("plan_limit", "seed", "max_items", "min_free_gib", "replan"):
        if hasattr(args, k):
            config[k] = getattr(args, k)
    if getattr(args, "budget_gib", None) is not None:
        config["budget_gib"] = args.budget_gib
        config["budget_bytes"] = int(args.budget_gib * GiB)
    if getattr(args, "plan", None):
        config["plan_id"] = args.plan
    try:
        rec = RunRecord.start("collect", source, config, roots)
        rec.write(roots.work)
    except Exception as exc:  # noqa: BLE001
        log.error(
            "collect setup failed: %s", _scrub(f"{type(exc).__name__}: {exc}", roots)
        )
        return 2
    log.info("collect %s %s run_id=%s", args.cmd, source, rec.run_id)

    # One collect process per source: taken before any Store/Ledger is opened,
    # so a second job never removes the first one's .part files or ledger.
    lock_fh = _take_lock(intake / source)
    if lock_fh is None:
        msg = f"source lock held by another collect run (intake/{source}/.lock)"
        log.error("%s; exiting %d without touching state", msg, EXIT_LOCKED)
        rec.finish("failed", error=msg)
        rec.write(roots.work)
        return EXIT_LOCKED
    try:
        return _main_locked(
            args, source, roots, intake, rec, transport, sleep, clock, disk_free
        )
    finally:
        lock_fh.close()


def _take_lock(folder: Path) -> IO[str] | None:
    folder.mkdir(parents=True, exist_ok=True)
    fh = open(folder / ".lock", "a")  # noqa: SIM115 - held for the whole run
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def _main_locked(
    args: argparse.Namespace,
    source: str,
    roots: Roots,
    intake: Path,
    rec: RunRecord,
    transport: Transport | None,
    sleep: Callable[[float], None] | None,
    clock: Callable[[], float] | None,
    disk_free: Callable[[Path], int] | None,
) -> int:

    http_cfg = HttpConfig()
    fetcher = Fetcher(
        transport or UrllibTransport(http_cfg),
        http_cfg,
        clock=clock,
        sleep=sleep,
        catalog_hosts=CATALOG_HOSTS[source],
        on_event=_event_logger,
    )
    stats: dict[str, Any] = {}
    dropped: dict[str, int] = {}
    status, error = "ok", None
    try:
        if args.cmd == "verify":
            vplan = load_plan(intake, source, args.plan)
            rec.config["plan_sha256"] = vplan.plan_sha256
            store = Store(roots.work, source, readonly=True)
            v = store.verify(args.plan)
            stats["n_plan_items"] = len(vplan.items)
            stats.update({k: v[k] for k in v if k != "mismatched_keys"})
            stats["n_mismatched_keys_listed"] = len(v["mismatched_keys"])
            for key in v["mismatched_keys"]:
                log.error("mismatch: %s", key)
            if v["n_mismatch"] or v["n_missing"] or v["n_bad_receipt"]:
                status, error = "failed", "verify found mismatched or missing files"
        else:
            plan = _get_plan(args, source, intake, fetcher, rec)
            stats["plan"] = plan.summary()
            stats["plan_dropped"] = dict(plan.dropped)
            per_repo = plan.stats.get("per_repo")
            if per_repo is not None:
                stats["plan_per_repo"] = per_repo
            dropped.update({f"plan_{k}": v for k, v in plan.dropped.items()})
            for k, n_drop in sorted(plan.dropped.items()):
                if k.startswith("repo_failed:"):
                    repo = k.split(":", 1)[1]
                    detail = (per_repo or {}).get(repo, {})
                    log.warning(
                        "REPO FAILED %s (%s): %s",
                        repo,
                        n_drop,
                        detail.get("error") if isinstance(detail, dict) else detail,
                    )
            if not plan.items:
                status, error = "failed", "plan has no items"
            elif args.cmd in ("run", "pull"):
                budget = int(args.budget_gib * GiB)
                ledger = Ledger(intake / source / "ledger.json", budget)
                store = Store(
                    roots.work,
                    source,
                    StoreConfig(min_free_gib=args.min_free_gib),
                    disk_free=disk_free,
                )
                res = pull(
                    plan,
                    fetcher,
                    ledger,
                    store,
                    PullConfig(
                        budget_bytes=budget,
                        max_items=args.max_items,
                        min_free_gib=args.min_free_gib,
                    ),
                    on_event=_event_logger,
                )
                stats.update(res.summary())
                stats["checkpoint"] = res.checkpoint
                stats["ledger"] = ledger.summary()
                stats["n_requests"] = fetcher.n_requests
                stats["tripped_hosts"] = sorted(fetcher.tripped_hosts)
                dropped.update({f"pull_{k}": v for k, v in res.failed.items()})
                log.info(
                    "pull stopped=%s ok=%d replayed=%d failed=%d spent=%d",
                    res.stopped,
                    res.n_ok,
                    res.n_replayed,
                    res.n_failed,
                    res.spent_bytes,
                )
                if res.stopped in FAILED_STOPS:
                    status, error = "failed", f"pull stopped: {res.stopped}"
    except Exception as exc:  # noqa: BLE001 - recorded, then exit nonzero
        status = "failed"
        error = _scrub(f"{type(exc).__name__}: {exc}", roots)
        log.error("collect %s failed: %s", args.cmd, error)
    if args.cmd != "verify":
        stats["catalog_bytes_by_host"] = dict(fetcher.catalog_bytes)
    rec.finish(status, stats=stats, dropped=dropped, error=error)
    rec.write(roots.work)
    log.info("run.json status=%s", status)
    return 0 if status == "ok" else 1


def _get_plan(
    args: argparse.Namespace,
    source: str,
    intake: Path,
    fetcher: Fetcher,
    rec: RunRecord,
) -> Plan:
    if args.cmd == "pull":
        plan = load_plan(intake, source, args.plan)
    else:
        params = {"plan_limit": args.plan_limit, "seed": args.seed}
        existing = None
        if args.cmd == "run" and not args.replan:
            existing = _find_plan(intake, source, params)
        if existing is not None:
            plan = load_plan(intake, source, existing)
            rec.config["plan_reused"] = True
            log.warning("reusing plan %s (pass --replan for a fresh one)", existing)
        else:
            mod = importlib.import_module(REGISTRY[source])
            cfg = mod.DEFAULT_CONFIG
            if args.plan_limit is not None:
                cfg = replace(cfg, max_packages=args.plan_limit)
            if args.seed is not None and "seed" in {
                f.name for f in dataclasses.fields(cfg)
            }:
                cfg = replace(cfg, seed=args.seed)
            result = mod.plan(fetcher.get, cfg)
            seed = 0 if args.seed is None else args.seed
            plan = make_plan(result, seed=seed, params=params)
            if not plan.items:
                rec.config["plan_id"] = plan.plan_id
                raise ValueError(
                    f"planner returned no items (dropped {dict(plan.dropped)}); "
                    "the empty plan is not written"
                )
            write_plan(plan, intake)
            log.info(
                "wrote plan %s (%d items, dropped %s)",
                plan.plan_id,
                len(plan.items),
                dict(plan.dropped),
            )
    rec.config["plan_id"] = plan.plan_id
    rec.config["plan_sha256"] = plan.plan_sha256
    return plan


if __name__ == "__main__":
    sys.exit(main())

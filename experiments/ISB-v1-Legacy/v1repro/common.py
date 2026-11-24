"""Paths, output-dir guard, run records and input hashes.

Run records never hold absolute paths: paths are written relative to the git
root, and the dataset root is recorded as ``env:ISB_DATA``.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

EXP_DIR = Path(__file__).resolve().parents[1]
GIT_ROOT = EXP_DIR.parents[1]
INPUTS_DIR = EXP_DIR / "inputs"
V1_RAW_DIR = EXP_DIR / "v1_raw"
RUNS_DIR = EXP_DIR / "runs"
LEGACY_V1 = GIT_ROOT / "Sherlock" / "legacy" / "V1"


class OutputDirRefused(ValueError):
    """An output directory that would overwrite or sit inside reference data."""


def protected_dirs() -> list[Path]:
    """Folders no run may write into."""
    dirs = [
        V1_RAW_DIR,
        INPUTS_DIR,
        GIT_ROOT / "Sherlock",
        GIT_ROOT / "ISB-Sherlock-Data",
    ]
    if os.environ.get("ISB_DATA"):
        dirs.append(Path(os.environ["ISB_DATA"]))
    return dirs


def check_output_dir(
    out_dir: Path, protected: list[Path] | None = None, require_empty: bool = True
) -> Path:
    """Resolve ``out_dir`` and refuse it if it is inside a protected folder.

    Symlinks are resolved before the check, so a link into ``inputs/`` is
    refused too. An existing non-empty folder is refused (runs never overwrite)
    unless ``require_empty`` is False, as for a run folder being checked.
    """
    resolved = Path(os.path.realpath(out_dir))
    for bad in protected if protected is not None else protected_dirs():
        bad_r = Path(os.path.realpath(bad))
        if resolved == bad_r or resolved.is_relative_to(bad_r):
            raise OutputDirRefused(
                f"output dir is inside a protected folder ({bad_r.name}/)"
            )
    if require_empty and resolved.exists() and any(resolved.iterdir()):
        raise OutputDirRefused("output dir exists and is not empty")
    return resolved


def new_run_id(now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.UTC)
    tag = now.strftime("%Y%m%dT%H%M%SZ")
    job = os.environ.get("SLURM_JOB_ID")
    return f"{tag}-j{job}" if job else tag


def utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def rel_to_root(path: Path) -> str:
    """A path for a run record: relative to the git root, never absolute."""
    resolved = Path(os.path.realpath(path))
    try:
        return "<git root>/" + resolved.relative_to(GIT_ROOT).as_posix()
    except ValueError:
        return "<outside git root>/" + resolved.name


def git_state(root: Path = GIT_ROOT) -> dict[str, Any]:
    def run(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    try:
        exp_status = run(
            "status", "--porcelain", "--", EXP_DIR.relative_to(root).as_posix()
        )
        return {
            "commit": run("rev-parse", "HEAD"),
            "dirty": bool(run("status", "--porcelain", "--untracked-files=no")),
            # Modified or untracked files in this experiment (inputs/ and runs/
            # are gitignored and never listed). Paths are relative to the root.
            "experiment_dirty": bool(exp_status),
            "experiment_status": exp_status.splitlines(),
        }
    except (OSError, subprocess.CalledProcessError) as exc:
        return {"commit": None, "error": type(exc).__name__}


def read_inputs_index(inputs: Path | None = None) -> dict[str, str]:
    """``INPUTS.sha256`` as {relative path: sha256}."""
    inputs = inputs or INPUTS_DIR
    index: dict[str, str] = {}
    for line in (inputs / "INPUTS.sha256").read_text().splitlines():
        if line.strip():
            digest, rel = line.split(maxsplit=1)
            index[rel.strip()] = digest
    return index


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def verified_inputs(rels: list[str], inputs: Path | None = None) -> dict[str, str]:
    """Hash each input and check it against ``INPUTS.sha256``; return the hashes."""
    inputs = inputs or INPUTS_DIR
    index = read_inputs_index(inputs)
    out: dict[str, str] = {}
    for rel in rels:
        got = sha256_file(inputs / rel)
        if index.get(rel) != got:
            raise RuntimeError(f"input {rel} does not match INPUTS.sha256")
        out[rel] = got
    return out


def write_json(path: Path, obj: Any, overwrite: bool = False) -> None:
    """Write JSON; refuses to replace an existing file unless ``overwrite``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w" if overwrite else "x") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_json_atomic(path: Path, obj: Any) -> None:
    """Write JSON through a temp file and ``os.replace``: readers never see half."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


#: Folders whose every file identifies the code of a run.
CODE_DIRS = ("v1repro", "drivers", "slurm", "tools")
HARNESS = LEGACY_V1 / "YaraGen" / "Detection" / "harness.py"


def code_hashes() -> dict[str, str]:
    """sha256 of every code file here and of V1's harness, by root-relative path."""
    files = [
        p
        for d in CODE_DIRS
        for p in sorted((EXP_DIR / d).rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    ]
    return {rel_to_root(p): sha256_file(p) for p in [*files, HARNESS]}


def yara_version() -> str | None:
    try:
        import yara
    except ImportError:
        return None
    return yara.__version__


def load_json(path: Path) -> Any:
    with open(path) as fh:
        return json.load(fh)


def run_record(
    stage: str,
    run_id: str,
    started: str,
    inputs: dict[str, str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "run_id": run_id,
        "started_utc": started,
        "finished_utc": utc_now(),
        "git": git_state(),
        "code_sha256": code_hashes(),
        "python": sys.version.split()[0],
        "yara_version": yara_version(),
        "slurm_job_id": os.environ.get("SLURM_JOB_ID"),
        "hash_randomization": sys.flags.hash_randomization,
        "inputs_sha256": inputs,
        **(extra or {}),
    }

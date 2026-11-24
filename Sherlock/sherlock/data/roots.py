"""Resolve the data, work, scratch and (optional) archive roots.

Every path Sherlock touches derives from four roots. Each is read from its
environment variable first (a variable set but empty is an error, not "unset"),
then from ``Sherlock/config/roots.yaml`` (gitignored,
written by ``setup.sh``). There are no defaults: a root that is not configured is
an error naming both places to set it, never a guess. V1's drivers hard-coded
corpus roots, and after the move to ramius every one of them pointed at a dead
old-cluster path; this module is why Sherlock has no such paths (H7, D6).

``zips`` (``ISB_ZIPS``) is optional. It is only needed while the dataset archives
are on disk; on ramius they were deleted after verification on 2026-11-23 and the
root is retired.

The dataset root must exist, since nothing can run without it. Work and scratch
roots are only required to be absolute: the test suite points them at
``tmp_path`` subfolders that the code under test creates.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ROOT_ENV",
    "REQUIRED_ROOTS",
    "DEFAULT_CONFIG_PATH",
    "Roots",
    "RootsError",
    "resolve_roots",
]

#: root name -> (environment variable, roots.yaml key).
ROOT_ENV: Mapping[str, tuple[str, str]] = {
    "dataset": ("ISB_DATA", "dataset_root"),
    "work": ("ISB_WORK", "work_root"),
    "scratch": ("ISB_SCRATCH", "scratch_root"),
    "zips": ("ISB_ZIPS", "zips_root"),
}

REQUIRED_ROOTS: tuple[str, ...] = ("dataset", "work", "scratch")

#: Keys roots.yaml may hold besides the roots themselves.
_OTHER_YAML_KEYS = frozenset({"tools"})

#: ``Sherlock/config/roots.yaml``, found from this file, never from the cwd.
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "roots.yaml"


class RootsError(ValueError):
    """A root is missing or malformed; the message says how to fix it."""


@dataclass(frozen=True)
class Roots:
    """The resolved roots. ``sources`` records where each one came from."""

    dataset: Path
    work: Path
    scratch: Path
    zips: Path | None = None
    #: root name -> "env:<VAR>" or "yaml:<key>", for run records.
    sources: dict[str, str] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": str(self.dataset),
            "work": str(self.work),
            "scratch": str(self.scratch),
            "zips": str(self.zips) if self.zips is not None else None,
            "sources": dict(self.sources),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Roots:
        zips = d.get("zips")
        return cls(
            dataset=Path(d["dataset"]),
            work=Path(d["work"]),
            scratch=Path(d["scratch"]),
            zips=Path(zips) if zips else None,
            sources=dict(d.get("sources") or {}),
        )

    def provenance(self) -> dict[str, dict[str, str | None] | None]:
        """Where each root came from and its folder name, never its absolute path.

        This is what run records store: an absolute path would put the cluster's
        layout and user name into artifacts that may be shared (brownie, 23 Nov).
        """
        out: dict[str, dict[str, str | None] | None] = {}
        for name in ROOT_ENV:
            path = getattr(self, name)
            out[name] = (
                None
                if path is None
                else {"source": self.sources.get(name), "dir": path.name}
            )
        return out

    def summary(self) -> dict[str, Any]:
        return self.provenance()


# -- resolution --------------------------------------------------------------


def _load_yaml(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return {}
    import yaml

    try:
        data = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise RootsError(
            f"{config_path} is not valid YAML ({exc}); fix it or rerun ./setup.sh "
            "--force from the git root"
        ) from None
    if not isinstance(data, dict):
        raise RootsError(f"{config_path} must be a mapping of root keys to paths")
    known = {key for _, key in ROOT_ENV.values()} | _OTHER_YAML_KEYS
    unknown = sorted(set(data) - known)
    if unknown:
        raise RootsError(
            f"{config_path} has unknown keys {unknown}; allowed: {sorted(known)}"
        )
    return data


def _missing_message(name: str, config_path: Path) -> str:
    var, key = ROOT_ENV[name]
    return (
        f"root '{name}' is not configured: set {var} in the environment or "
        f"'{key}' in {config_path} (run ./setup.sh from the git root to write "
        "roots.yaml). There is no default."
    )


def resolve_roots(
    env: Mapping[str, str] | None = None,
    config_path: Path | None = None,
) -> Roots:
    """Resolve every root: environment variable first, then roots.yaml.

    ``env`` defaults to ``os.environ`` and ``config_path`` to
    :data:`DEFAULT_CONFIG_PATH`; tests pass both so they never see the real ones.
    """
    env = os.environ if env is None else env
    config_path = DEFAULT_CONFIG_PATH if config_path is None else config_path
    data = _load_yaml(config_path)

    values: dict[str, Path | None] = {}
    sources: dict[str, str] = {}
    for name, (var, key) in ROOT_ENV.items():
        raw: Any = env.get(var)
        source = f"env:{var}"
        if raw is not None and not str(raw).strip():
            raise RootsError(
                f"{var} is set but empty; unset it to use '{key}' from "
                f"{config_path}, or set it to an absolute path"
            )
        if raw is None:
            raw = data.get(key) or None
            source = f"yaml:{key}"
        if raw is None:
            if name in REQUIRED_ROOTS:
                raise RootsError(_missing_message(name, config_path))
            values[name] = None
            continue
        path = Path(str(raw)).expanduser()
        if not path.is_absolute():
            raise RootsError(
                f"root '{name}' ({source}) must be an absolute path, got {raw!r}"
            )
        values[name] = path
        sources[name] = source

    dataset = values["dataset"]
    assert dataset is not None
    if not dataset.is_dir():
        raise RootsError(
            f"dataset root {dataset} ({sources['dataset']}) is not a directory; "
            "fix ISB_DATA or dataset_root"
        )
    work, scratch = values["work"], values["scratch"]
    assert work is not None and scratch is not None
    return Roots(
        dataset=dataset,
        work=work,
        scratch=scratch,
        zips=values["zips"],
        sources=sources,
    )

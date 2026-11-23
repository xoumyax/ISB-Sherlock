"""Unit tests for ``sherlock.data.roots``: env first, then roots.yaml, no defaults.

Every test injects its own environment mapping and config path, so the suite runs
on a fresh clone with no ``config/roots.yaml`` and ignores the real one when it
exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sherlock.data.roots import ROOT_ENV, Roots, RootsError, resolve_roots


def _write_yaml(path: Path, **keys: str) -> Path:
    path.write_text("".join(f"{k}: {v}\n" for k, v in keys.items()))
    return path


def _dirs(tmp_path: Path) -> dict[str, Path]:
    out = {}
    for name in ("data", "work", "scratch"):
        d = tmp_path / name
        d.mkdir()
        out[name] = d
    return out


def test_env_wins_over_yaml(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    other = tmp_path / "other_data"
    other.mkdir()
    cfg = _write_yaml(
        tmp_path / "roots.yaml",
        dataset_root=str(other),
        work_root=str(d["work"]),
        scratch_root=str(d["scratch"]),
    )
    roots = resolve_roots(env={"ISB_DATA": str(d["data"])}, config_path=cfg)
    assert roots.dataset == d["data"]
    assert roots.work == d["work"]
    assert roots.scratch == d["scratch"]
    assert roots.zips is None
    assert roots.sources["dataset"] == "env:ISB_DATA"
    assert roots.sources["work"] == "yaml:work_root"


def test_yaml_only(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    cfg = _write_yaml(
        tmp_path / "roots.yaml",
        dataset_root=str(d["data"]),
        work_root=str(d["work"]),
        scratch_root=str(d["scratch"]),
    )
    roots = resolve_roots(env={}, config_path=cfg)
    assert roots.dataset == d["data"]


def test_env_only_without_yaml(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    env = {
        "ISB_DATA": str(d["data"]),
        "ISB_WORK": str(d["work"]),
        "ISB_SCRATCH": str(d["scratch"]),
    }
    roots = resolve_roots(env=env, config_path=tmp_path / "absent.yaml")
    assert roots.work == d["work"]


def test_missing_root_says_how_to_fix(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    env = {"ISB_DATA": str(d["data"]), "ISB_SCRATCH": str(d["scratch"])}
    with pytest.raises(RootsError) as exc:
        resolve_roots(env=env, config_path=tmp_path / "absent.yaml")
    msg = str(exc.value)
    assert "ISB_WORK" in msg
    assert "work_root" in msg
    assert "setup.sh" in msg


def test_roots_error_is_value_error() -> None:
    assert issubclass(RootsError, ValueError)


def test_no_defaults_empty_value_is_missing(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    env = {
        "ISB_DATA": "",
        "ISB_WORK": str(d["work"]),
        "ISB_SCRATCH": str(d["scratch"]),
    }
    with pytest.raises(RootsError, match="ISB_DATA"):
        resolve_roots(env=env, config_path=tmp_path / "absent.yaml")


def test_relative_root_rejected(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    env = {
        "ISB_DATA": "relative/data",
        "ISB_WORK": str(d["work"]),
        "ISB_SCRATCH": str(d["scratch"]),
    }
    with pytest.raises(RootsError, match="absolute"):
        resolve_roots(env=env, config_path=tmp_path / "absent.yaml")


def test_dataset_root_must_exist(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    env = {
        "ISB_DATA": str(tmp_path / "nope"),
        "ISB_WORK": str(d["work"]),
        "ISB_SCRATCH": str(d["scratch"]),
    }
    with pytest.raises(RootsError, match="not a directory"):
        resolve_roots(env=env, config_path=tmp_path / "absent.yaml")


def test_zips_optional_and_read_when_set(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    zips = tmp_path / "zips"
    zips.mkdir()
    env = {
        "ISB_DATA": str(d["data"]),
        "ISB_WORK": str(d["work"]),
        "ISB_SCRATCH": str(d["scratch"]),
        "ISB_ZIPS": str(zips),
    }
    roots = resolve_roots(env=env, config_path=tmp_path / "absent.yaml")
    assert roots.zips == zips


def test_unknown_yaml_key_rejected(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    cfg = _write_yaml(
        tmp_path / "roots.yaml",
        dataset_root=str(d["data"]),
        work_root=str(d["work"]),
        scratch_root=str(d["scratch"]),
        data_root="/typo",
    )
    with pytest.raises(RootsError, match="data_root"):
        resolve_roots(env={}, config_path=cfg)


def test_tools_section_is_allowed(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    cfg = tmp_path / "roots.yaml"
    cfg.write_text(
        f"dataset_root: {d['data']}\nwork_root: {d['work']}\n"
        f"scratch_root: {d['scratch']}\ntools:\n  sdhash: third_party/x\n"
    )
    roots = resolve_roots(env={}, config_path=cfg)
    assert roots.dataset == d["data"]


def test_to_dict_round_trip(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    roots = Roots(dataset=d["data"], work=d["work"], scratch=d["scratch"])
    again = Roots.from_dict(roots.to_dict())
    assert again.to_dict() == roots.to_dict()
    assert roots.to_dict()["zips"] is None


def test_env_names_cover_every_root() -> None:
    assert set(ROOT_ENV) == {"dataset", "work", "scratch", "zips"}
    assert ROOT_ENV["dataset"] == ("ISB_DATA", "dataset_root")
    assert ROOT_ENV["zips"] == ("ISB_ZIPS", "zips_root")


# -- review fixes (session 2) -------------------------------------------------


def test_empty_env_does_not_fall_through_to_yaml(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    cfg = _write_yaml(
        tmp_path / "roots.yaml",
        dataset_root=str(d["data"]),
        work_root=str(d["work"]),
        scratch_root=str(d["scratch"]),
    )
    with pytest.raises(RootsError, match="ISB_DATA is set but empty"):
        resolve_roots(env={"ISB_DATA": ""}, config_path=cfg)


def test_malformed_yaml_is_roots_error(tmp_path: Path) -> None:
    cfg = tmp_path / "roots.yaml"
    cfg.write_text("dataset_root: [unclosed\n")
    with pytest.raises(RootsError, match="roots.yaml"):
        resolve_roots(env={}, config_path=cfg)


def test_provenance_has_no_absolute_paths(tmp_path: Path) -> None:
    d = _dirs(tmp_path)
    env = {
        "ISB_DATA": str(d["data"]),
        "ISB_WORK": str(d["work"]),
        "ISB_SCRATCH": str(d["scratch"]),
    }
    prov = resolve_roots(env=env, config_path=tmp_path / "absent.yaml").provenance()
    assert prov == {
        "dataset": {"source": "env:ISB_DATA", "dir": "data"},
        "work": {"source": "env:ISB_WORK", "dir": "work"},
        "scratch": {"source": "env:ISB_SCRATCH", "dir": "scratch"},
        "zips": None,
    }
    assert str(tmp_path) not in str(prov)

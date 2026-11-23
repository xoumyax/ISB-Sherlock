"""Run V1's own test suites against the V1 reference code in ``legacy/V1``.

The test files in this folder are V1's, copied verbatim. They stay that way:
they are the record of what V1 guaranteed, and a green run here is the health
check for the parity oracle that gate G2 relies on. Everything needed to make
them run in the new layout lives in this conftest:

* ``legacy/V1`` goes first on ``sys.path`` and on ``PYTHONPATH`` (two V1 tests
  import the package in a subprocess), and the import is checked to resolve
  there, so a full YaraGen checkout elsewhere on the path can't be tested by
  mistake.
* Tests that import ``YaraGen.StaticFeatures`` skip with a stated reason when
  that package is absent. It was not part of the V1-Legacy archive; copy it to
  ``legacy/V1/YaraGen/StaticFeatures/`` and they run.
* Every test here is marked ``legacy``.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import sys
from pathlib import Path

import pytest

LEGACY_ROOT = Path(__file__).resolve().parents[2] / "legacy" / "V1"

if not (LEGACY_ROOT / "YaraGen" / "ISB" / "__init__.py").is_file():
    raise pytest.UsageError(
        f"V1 reference code not found at {LEGACY_ROOT}/YaraGen/ISB; "
        "see DIRECTORY_MAP.md (legacy/V1).")

if str(LEGACY_ROOT) not in sys.path:
    sys.path.insert(0, str(LEGACY_ROOT))
_pythonpath = os.environ.get("PYTHONPATH", "")
if str(LEGACY_ROOT) not in _pythonpath.split(os.pathsep):
    os.environ["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(LEGACY_ROOT), _pythonpath) if p)

_isb = importlib.import_module("YaraGen.ISB")
_resolved = Path(_isb.__file__).resolve()
if LEGACY_ROOT.resolve() not in _resolved.parents:
    raise pytest.UsageError(
        f"YaraGen.ISB resolved to {_resolved}, not to legacy/V1. Another "
        "YaraGen is shadowing the reference copy; remove it from sys.path.")

_LEGACY_TESTS = Path(__file__).resolve().parent

HAVE_STATIC_FEATURES = (
    importlib.util.find_spec("YaraGen.StaticFeatures") is not None)


def _uses_static_features(item) -> bool:
    func = getattr(item, "function", None)
    if func is None:
        return False
    try:
        return "YaraGen.StaticFeatures" in inspect.getsource(func)
    except (OSError, TypeError):
        return False


def pytest_collection_modifyitems(config, items):
    skip_sf = pytest.mark.skip(
        reason="YaraGen.StaticFeatures was not migrated with V1-Legacy; copy "
               "it to legacy/V1/YaraGen/StaticFeatures/ to run this test")
    for item in items:
        if _LEGACY_TESTS not in Path(item.path).resolve().parents:
            continue
        item.add_marker(pytest.mark.legacy)
        if not HAVE_STATIC_FEATURES and _uses_static_features(item):
            item.add_marker(skip_sf)

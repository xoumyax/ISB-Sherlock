"""Suite-wide pytest setup for Sherlock.

Three rules hold for every test:

* The repository root is importable, so ``import sherlock`` works without
  installing the package.
* No test writes to a real root. ``ISB_WORK`` and ``ISB_SCRATCH`` point into
  the test's own ``tmp_path`` unless the test is marked ``needs_data``.
* Tests that read the real dataset are marked ``needs_data`` and skip unless
  ``ISB_DATA`` names an existing directory. They may read it, never write it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(autouse=True)
def _redirect_writable_roots(request, tmp_path, monkeypatch):
    """Point every writable root at ``tmp_path`` for the duration of a test."""
    if request.node.get_closest_marker("needs_data") is None:
        monkeypatch.setenv("ISB_WORK", str(tmp_path / "work"))
        monkeypatch.setenv("ISB_SCRATCH", str(tmp_path / "scratch"))
    yield


def pytest_collection_modifyitems(config, items):
    data_root = os.environ.get("ISB_DATA", "")
    have_data = bool(data_root) and Path(data_root).is_dir()
    skip_data = pytest.mark.skip(
        reason="needs_data: set ISB_DATA to the dataset root to run this test"
    )
    for item in items:
        if item.get_closest_marker("needs_data") and not have_data:
            item.add_marker(skip_data)

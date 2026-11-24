"""Fakes only: every test gets a synthetic ISB_DATA in tmp_path, never the real one."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

EXP_DIR = Path(__file__).resolve().parents[1]
if str(EXP_DIR) not in sys.path:
    sys.path.insert(0, str(EXP_DIR))


@pytest.fixture(autouse=True)
def fake_isb_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "fake_isb_data"
    (root / "metadata").mkdir(parents=True)
    monkeypatch.setenv("ISB_DATA", str(root))
    return root

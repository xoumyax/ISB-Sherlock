"""The per-source budget ledger (COLLECT §2 Ledger)."""

from __future__ import annotations

import pytest

from sherlock.collect.ledger import BudgetExhausted, Ledger, LedgerConfig

MiB = 1 << 20


def _ledger(tmp_path, budget=10 * MiB, **cfg):
    return Ledger(tmp_path / "ledger.json", budget, LedgerConfig(**cfg))


def test_success_charges_bytes_read_and_releases_rest(tmp_path):
    led = _ledger(tmp_path)
    assert led.reserve("a", 1000) == 1000
    assert led.remaining == 10 * MiB - 1000
    led.settle("a", 900, ok=True)
    assert led.spent == 900
    assert led.remaining == 10 * MiB - 900


def test_refund_only_pre_payload_failures(tmp_path):
    led = _ledger(tmp_path)
    led.reserve("a", 1000)
    led.settle("a", 0, ok=False)
    assert led.spent == 0
    led.reserve("b", 1000)
    led.settle("b", 1, ok=False)
    assert led.spent == 1000


def test_partial_body_charges_reservation(tmp_path):
    led = _ledger(tmp_path)
    led.reserve("a", 5000)
    led.settle("a", 1234, ok=False)
    assert led.spent == 5000


def test_unknown_size_reserves_default_and_overrun_charges_full(tmp_path):
    led = _ledger(tmp_path, budget=2000 * MiB, unknown_size_reserve_bytes=512 * MiB)
    assert led.reserve("a", None) == 512 * MiB
    led.settle("a", 512 * MiB + 1, ok=False)  # caller aborted the stream
    assert led.spent == 512 * MiB


def test_reserve_over_remaining_raises(tmp_path):
    led = _ledger(tmp_path, budget=1000)
    with pytest.raises(BudgetExhausted):
        led.reserve("a", 1001)
    assert led.spent == 0


def test_survives_reload_and_orphans_charged(tmp_path):
    led = _ledger(tmp_path)
    led.reserve("a", 100)
    led.settle("a", 100, ok=True)
    led.reserve("b", 700)  # process dies here
    again = _ledger(tmp_path)
    assert again.spent == 800
    assert again.summary()["n_orphans_charged"] == 1


def test_budget_can_be_raised_on_reload(tmp_path):
    led = _ledger(tmp_path, budget=1000)
    led.reserve("a", 900)
    led.settle("a", 900, ok=True)
    again = _ledger(tmp_path, budget=5000)
    assert again.remaining == 4100


def test_settle_unknown_key_raises(tmp_path):
    led = _ledger(tmp_path)
    with pytest.raises(ValueError):
        led.settle("nope", 1, ok=True)


def test_unknown_size_failure_charges_bytes_read_not_full_reserve(tmp_path):
    led = _ledger(tmp_path, budget=2000 * MiB, unknown_size_reserve_bytes=512 * MiB)
    led.reserve("a", None)
    assert led.settle("a", 3 * MiB, ok=False) == 3 * MiB
    led.reserve("b", 1000)  # declared size: a partial body keeps the reservation
    assert led.settle("b", 10, ok=False) == 1000


def test_unknown_size_orphan_still_charged_in_full(tmp_path):
    led = _ledger(tmp_path, budget=2000 * MiB, unknown_size_reserve_bytes=512 * MiB)
    led.reserve("a", None)
    again = _ledger(tmp_path, budget=2000 * MiB)
    assert again.spent == 512 * MiB

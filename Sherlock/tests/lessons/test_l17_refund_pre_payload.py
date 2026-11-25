"""L17: refund only pre-payload failures.

The V1-era kit's reservations were never released and ate its 8 GiB cap. Here a
failure before the first payload byte is refunded; one after it keeps the whole
reservation (bytes moved), and a success charges what was read.
"""

from __future__ import annotations

from sherlock.collect.ledger import Ledger


def test_refund_only_pre_payload_failures(tmp_path) -> None:
    led = Ledger(tmp_path / "ledger.json", 10_000)
    led.reserve("refund", 1000)
    assert led.settle("refund", 0, ok=False) == 0
    led.reserve("partial", 1000)
    assert led.settle("partial", 1, ok=False) == 1000
    led.reserve("ok", 1000)
    assert led.settle("ok", 900, ok=True) == 900
    assert led.spent == 1900 and led.reserved == 0

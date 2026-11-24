"""Compile and scan with V1's own ``Detection.harness`` from ``Sherlock/legacy/V1``.

The harness is used unmodified with its default ``DetectionConfig`` (30 s
per-file timeout, 10,000-string cap). yara's "too many matches" RuntimeWarnings
are counted, never escalated: the harness turns any exception from
``rules.match`` into a ``scan_error``, which would change the result.
"""

from __future__ import annotations

import sys
import time
import warnings
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

from .common import LEGACY_V1
from .targets import TargetSpec
from .units import to_rule_units


def load_harness(legacy_root: Path = LEGACY_V1) -> ModuleType:
    """Import ``YaraGen.Detection.harness`` from ``legacy/V1`` and check its origin."""
    # Never leave bytecode beside the read-only legacy code.
    sys.dont_write_bytecode = True
    root = str(legacy_root)
    if root not in sys.path:
        sys.path.insert(0, root)
    from YaraGen.Detection import harness

    origin = Path(harness.__file__).resolve()
    if not origin.is_relative_to(legacy_root.resolve()):
        raise RuntimeError("YaraGen.Detection.harness resolved outside legacy/V1")
    return harness


class WarningCounter:
    """A ``warnings.showwarning`` replacement that only counts."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()

    def show(
        self, message: Warning | str, category: type[Warning], *_a: Any, **_k: Any
    ) -> None:
        text = str(message)
        key = "too_many_matches" if "too many matches" in text else category.__name__
        self.counts[key] += 1


@contextmanager
def counting_warnings() -> Iterator[WarningCounter]:
    counter = WarningCounter()
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.showwarning = counter.show
        yield counter


def scan_targets(harness: ModuleType, specs: Sequence[TargetSpec]) -> list:
    return [
        harness.ScanTarget(
            sha256=t.sha256, path=t.path, kind=t.kind, family=t.family, source=t.source
        )
        for t in specs
    ]


def compile_units(
    units: Sequence[Mapping[str, Any]], progress: Callable[[str], None] | None = None
) -> tuple[Any, dict[str, Any]]:
    """Compile ``units`` in a fresh harness; return (harness, compile summary)."""
    hmod = load_harness()
    h = hmod.DetectionHarness(hmod.DetectionConfig(), progress=progress)
    t0 = time.time()
    summary = h.compile(to_rule_units(units, hmod.RuleUnit))
    summary["compile_seconds"] = round(time.time() - t0, 1)
    return h, summary


def run_scan(
    units: Sequence[Mapping[str, Any]],
    targets: Mapping[str, Sequence[TargetSpec]],
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Compile, then ``harness.score(held, goodware, gen)`` as V1 called it."""
    hmod = load_harness()
    h, summary = compile_units(units, progress)
    t0 = time.time()
    with counting_warnings() as wc:
        res = h.score(
            scan_targets(hmod, targets["held"]),
            scan_targets(hmod, targets["goodware"]),
            gen=scan_targets(hmod, targets["gen"]),
        )
    res["compile"] = summary
    res["scan_seconds"] = round(time.time() - t0, 1)
    res["warnings"] = dict(wc.counts)
    res["n_targets"] = {k: len(v) for k, v in targets.items()}
    return res

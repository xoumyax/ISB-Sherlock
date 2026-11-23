"""L12: leakage guards raise; they never warn and never default off.

V1 measured it (pooling.py, supervision.py): a guard whose argument defaults to
``None`` is an accidental off-switch. Sherlock's guard has no off-switch at all.
Until the split exists (G1), every caller that asks for training families gets an
error, which is the only safe answer before anything is placed.
"""

from __future__ import annotations

import pytest

from sherlock.data.manifest import LeakageError, Split, require_training_families

_SPLIT = Split.from_dict(
    {"fam_train": "F_train", "fam_dev": "F_dev", "fam_test": "F_test"}
)


@pytest.mark.parametrize("family", ["fam_dev", "fam_test"])
def test_eval_family_cannot_label(family: str) -> None:
    with pytest.raises(LeakageError, match=family):
        require_training_families(["fam_train", family], _SPLIT, purpose="labels")


def test_unplaced_family_cannot_label() -> None:
    with pytest.raises(LeakageError, match="fam_new"):
        require_training_families(["fam_new"], _SPLIT, purpose="labels")


def test_no_split_means_no_training_families() -> None:
    # Fail closed: before G1 there is no F_train, so nothing may be labelled.
    with pytest.raises(LeakageError, match="G1"):
        require_training_families(["fam_train"], None, purpose="labels")


def test_guard_has_no_off_switch() -> None:
    import inspect

    params = inspect.signature(require_training_families).parameters
    assert set(params) == {"families", "split", "purpose"}

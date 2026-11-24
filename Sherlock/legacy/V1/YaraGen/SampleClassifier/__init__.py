"""SampleClassifier — the feature-discovery engines for Exp 2 (EXP2_DESIGN §4).

Named ``SampleClassifier``, not ``Classifier``: ``YaraGen/Classifier`` already
means the *rule* classifier. These classify *samples*.

Two complementary models, and running both is the point:

* **(A) :mod:`model_a`** — string-presence LightGBM over the M1 extraction cache.
  Cheap, CPU, attributes directly to strings. Doubles as the sanity baseline: if
  the byte model cannot beat string presence, byte-level discovery bought nothing.
* **(B) :mod:`model`/:mod:`train`** — window-strided MalConv over raw bytes. Finds
  hex-pattern candidates no string extractor emits (code sequences, packer stubs,
  header quirks), via :mod:`attribute`.

Both carry two heads (malware-vs-goodware, family-over-F_train) and both
attribution scores travel with every candidate into ISB-A.

**Leakage is enforced in code**, not convention: :class:`~.data.ClassifierDataspec`
asserts that no F_dev/F_test family and no G_eval goodware can reach training. A
leak here would invalidate every number in Exp 2 and would show up only as a
suspiciously good result.

:mod:`data` deliberately imports no torch, so the split logic and leakage guards
stay testable without loading CUDA.

SAFETY: sample bytes are read with ``open(rb)`` and never executed.
"""

from .data import (
    FAMILY_UNLABELED,
    KNOWN_SINGLETON_FAMILIES,
    ClassifierDataspec,
    DataConfig,
    SampleRef,
    WindowSampler,
    read_windows,
)

__all__ = [
    "ClassifierDataspec", "DataConfig", "SampleRef", "WindowSampler",
    "read_windows", "FAMILY_UNLABELED", "KNOWN_SINGLETON_FAMILIES",
]


def __getattr__(name: str):
    """Lazily expose the torch/LightGBM pieces.

    Keeps ``import YaraGen.SampleClassifier`` cheap and torch-free for callers
    that only need the split logic (drivers, tests, the leakage guards).
    """
    lazy = {
        "ModelConfig": ".model", "WindowMalConv": ".model",
        "masked_family_loss": ".model", "PAD_BYTE": ".model",
        "WindowDataset": ".dataset", "collate_windows": ".dataset",
        "ClassifierTrainer": ".train", "TrainConfig": ".train",
        "variant_name": ".train", "load_checkpoint": ".train",
        "ModelAConfig": ".model_a", "StringPresenceClassifier": ".model_a",
        "AttributionConfig": ".attribute", "Attributor": ".attribute",
        "AttributedSpan": ".attribute",
    }
    if name in lazy:
        import importlib
        module = importlib.import_module(lazy[name], __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

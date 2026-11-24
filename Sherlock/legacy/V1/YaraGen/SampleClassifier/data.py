"""Datasets for the feature-discovery classifiers, with leakage enforced in code.

**The leakage protocol is the whole point of this module** (EXP2_DESIGN §4). The
classifier may train on ``F_train`` families' samples and ``G_stats`` goodware
only. F_dev and F_test families -- and every ``held`` half of every family -- are
never seen. At rule-build time attribution runs on a target family's ``gen``
samples with frozen weights that have never seen that family, which is what makes
the discovered features legitimate rather than memorised.

Convention ("leakage as code, not convention"): :class:`ClassifierDataspec`
*asserts* the property in its constructor rather than trusting the caller to have
filtered correctly. A silent leak here would invalidate every number in Exp 2,
and it would be invisible -- the model would simply look good.

SAFETY: sample bytes are read with ``open(rb)`` and never executed.
"""

from __future__ import annotations

import csv
import json
import os
import random
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

__all__ = [
    "SampleRef",
    "DataConfig",
    "ClassifierDataspec",
    "WindowSampler",
    "read_windows",
    "KNOWN_SINGLETON_FAMILIES",
]

#: Families the frozen split dropped for ``min_family_size=10`` but which still
#: carry a real family label. Brownie's call (2026-08-09): include them, binary
#: head only -- free malware-side signal, and no leakage risk because none is an
#: F_dev/F_test family.
KNOWN_SINGLETON_FAMILIES = (
    "phobos", "darkside", "teambot", "nable", "blacklotus", "bottomloader",
    "phoenixrat",
)

#: Sentinel family label meaning "no family supervision for this sample".
#: The family head's loss is masked wherever this appears.
FAMILY_UNLABELED = -1


@dataclass(frozen=True)
class SampleRef:
    """One training sample: where it is, what it is, how much it counts."""

    sha256: str
    path: str
    label: int                      # 1 = malware, 0 = goodware
    family: str | None = None
    family_index: int = FAMILY_UNLABELED
    weight: float = 1.0
    origin: str = ""                # labeled | singleton | goodware | vault
    meta: dict[str, Any] = field(default_factory=dict)


#: V1's corpus root, from the environment (no absolute path in the repo; brownie,
#: 23 Nov 2026). Unset means "" and the paths below are relative and unresolved.
_CORPUS = os.environ.get("ISB_V1_CORPUS", "")


@dataclass(frozen=True)
class DataConfig:
    corpus_root: str = _CORPUS
    manifest: str = os.path.join(_CORPUS, "_manifest", "corpus_manifest.csv")
    collisions: str = os.path.join(_CORPUS, "_manifest", "cross_label_collisions.csv")
    malware_split: str = ""
    goodware_split: str = ""

    #: Sweep axis (EXP2_DESIGN §4): include unlabeled vault mass, weighted down.
    vault: bool = False
    vault_weight: float = 0.3
    #: Leakage screen for the vault arm (built at the 2026-08-09 M2 gate review).
    #: The vault is unlabeled malware, so it can contain members of F_dev/F_test
    #: families -- training on them, even unlabeled, means the classifier HAS seen
    #: eval families. The screen lists vault shas whose imphash uniquely
    #: fingerprints one eval family. REQUIRED whenever ``vault=True``.
    vault_screen: str = ""
    #: Explicit override for running the vault arm with no screen. Only for
    #: measuring the size of the leak; never for a reported result.
    allow_unscreened_vault: bool = False
    #: PE-only both sides -- the vault is full of zips.
    pe_only: bool = True
    include_singletons: bool = True
    #: Fraction of F_train families' samples and G_stats held back for the
    #: within-distribution validation of the family head.
    holdout_frac: float = 0.1
    seed: int = 20260809


class ClassifierDataspec:
    """Builds the training/validation sample lists and asserts non-leakage.

    Validation follows EXP2_DESIGN §4: the *binary* head is validated on F_dev
    families plus a G_stats holdout -- unseen families are the deployment
    condition, so validating on seen families would flatter the model. The
    *family* head is validated on a within-F_train holdout, since F_dev families
    have no label in the family label space by construction.
    """

    def __init__(self, config: DataConfig):
        self.config = config
        self._rng = random.Random(config.seed)

        self.malware_split = _load_json(config.malware_split)
        self.goodware_split = _load_json(config.goodware_split)

        self.families_by_split = _families_by_split(self.malware_split)
        #: The family label space: F_train families only, sorted for determinism.
        self.family_names: list[str] = sorted(self.families_by_split["F_train"])
        self.family_to_index = {f: i for i, f in enumerate(self.family_names)}

        self.forbidden_families = (
            set(self.families_by_split["F_dev"]) | set(self.families_by_split["F_test"])
        )

        self.train: list[SampleRef] = []
        self.val_binary: list[SampleRef] = []
        self.val_family: list[SampleRef] = []
        self._screened_shas: set[str] = set()
        self._build()
        self._assert_no_leakage()

    # -- construction --------------------------------------------------
    def _build(self) -> None:
        cfg = self.config
        root = cfg.corpus_root

        f_train_samples: list[SampleRef] = []
        f_dev_samples: list[SampleRef] = []
        for sha, info in sorted(self.malware_split["samples"].items()):
            if cfg.pe_only and not info.get("is_pe"):
                continue
            family = info.get("family")
            split = info.get("split")
            ref = SampleRef(
                sha256=sha,
                path=os.path.join(root, info["path"]),
                label=1,
                family=family,
                family_index=self.family_to_index.get(family, FAMILY_UNLABELED),
                origin="labeled",
                meta={"split": split, "side": info.get("side")},
            )
            if split == "F_train":
                # Both gen and held: evaluation never touches F_train families,
                # so using their held half as training mass costs nothing.
                f_train_samples.append(ref)
            elif split == "F_dev":
                f_dev_samples.append(ref)
            # F_test is never materialised at all.

        g_stats, g_eval = self._goodware_refs()

        # -- within-distribution holdouts (seeded) ---------------------
        # Only family-labeled samples are eligible for the holdout: it exists to
        # validate the family head, and a singleton has no label in the 23-class
        # space, so holding one out would waste it in both roles.
        train_mal, hold_mal = _split_frac(
            f_train_samples, cfg.holdout_frac, self._rng)
        train_good, hold_good = _split_frac(g_stats, cfg.holdout_frac, self._rng)

        if cfg.include_singletons:
            train_mal = train_mal + self._singleton_refs()

        self.train = train_mal + train_good
        if cfg.vault:
            self.train.extend(self._vault_refs())

        # Binary head: unseen families (F_dev) + goodware holdout.
        self.val_binary = f_dev_samples + hold_good
        # Family head: within-F_train holdout, labelled samples only.
        self.val_family = [r for r in hold_mal if r.family_index != FAMILY_UNLABELED]

        self._g_eval_shas = {r.sha256 for r in g_eval}

    def _singleton_refs(self) -> list[SampleRef]:
        """The 7 dropped known-family samples, binary head only.

        They sit outside the 23-family label space, so ``family_index`` stays
        ``FAMILY_UNLABELED`` and the family loss is masked -- they contribute
        malware-ness signal without inventing label classes.
        """
        cfg = self.config
        wanted = set(KNOWN_SINGLETON_FAMILIES)
        out: list[SampleRef] = []
        for row in _read_manifest(cfg.manifest):
            if row.get("label") != "malware" or row.get("corpus") == "malwarevault":
                continue
            if cfg.pe_only and row.get("is_pe") != "1":
                continue
            fam = _normalize_family(row.get("family"))
            if fam not in wanted:
                continue
            sha = row.get("sha256")
            if not sha or sha in self.malware_split["samples"]:
                continue
            out.append(SampleRef(
                sha256=sha,
                path=os.path.join(cfg.corpus_root, row["rel_path"]),
                label=1,
                family=fam,
                family_index=FAMILY_UNLABELED,
                origin="singleton",
                meta={"split": "F_train_extra"},
            ))
        return _dedupe_by_sha(out)

    def _goodware_refs(self) -> tuple[list[SampleRef], list[SampleRef]]:
        cfg = self.config
        g_stats, g_eval = [], []
        for sha, info in sorted(self.goodware_split["samples"].items()):
            if cfg.pe_only and not info.get("is_pe"):
                continue
            ref = SampleRef(
                sha256=sha,
                path=os.path.join(cfg.corpus_root, info["path"]),
                label=0,
                origin="goodware",
                meta={"source": info.get("source"), "side": info.get("side")},
            )
            (g_stats if info.get("side") == "G_stats" else g_eval).append(ref)
        return g_stats, g_eval

    def _vault_refs(self) -> list[SampleRef]:
        """Unlabeled vault mass at ``vault_weight``, screened for leakage.

        Three exclusions, for three different reasons:

        * **The 16 cross-label collisions** -- benign runtime files that also live
          in the vault. Training on them as malware would teach the model that
          ``msvcr71.dll`` is malicious.
        * **Anything already in a split** -- it is labeled, so it belongs to the
          labeled arm at weight 1.0, not here at 0.3.
        * **The leakage screen** -- vault samples whose imphash uniquely
          fingerprints an F_dev/F_test family. These are almost certainly members
          of an eval family, and training on them (even unlabeled) breaks the
          leakage protocol: the F_dev AUC would be measured on families the model
          had effectively seen.

        The screen is mandatory here rather than advisory, per the same principle
        as the pooling leakage guard -- a defaulted-off leakage protection is an
        accidental off-switch.
        """
        cfg = self.config
        excluded = _collision_shas(cfg.collisions)
        excluded |= set(self.goodware_split["samples"])
        excluded |= set(self.malware_split["samples"])

        screened = _screen_shas(cfg.vault_screen)
        if not screened and not cfg.allow_unscreened_vault:
            raise ValueError(
                "vault=True requires vault_screen (a leakage screen listing vault "
                "shas whose imphash fingerprints an F_dev/F_test family). Pass "
                "allow_unscreened_vault=True only to measure the size of the leak."
            )
        self._screened_shas = screened
        excluded |= screened

        out: list[SampleRef] = []
        seen: set[str] = set()
        for row in _read_manifest(cfg.manifest):
            if row.get("corpus") != "malwarevault":
                continue
            if cfg.pe_only and row.get("is_pe") != "1":
                continue
            sha = row.get("sha256")
            if not sha or sha in excluded or sha in seen:
                continue
            seen.add(sha)
            out.append(SampleRef(
                sha256=sha,
                path=os.path.join(cfg.corpus_root, row["rel_path"]),
                label=1,
                family=None,
                family_index=FAMILY_UNLABELED,
                weight=cfg.vault_weight,
                origin="vault",
            ))
        return out

    # -- the guard -----------------------------------------------------
    def _assert_no_leakage(self) -> None:
        """Hard assertions. These must fire before training, not after."""
        held_forbidden = []
        for ref in self.train:
            if ref.family and ref.family in self.forbidden_families:
                held_forbidden.append((ref.sha256, ref.family))
        if held_forbidden:
            raise AssertionError(
                f"LEAKAGE: {len(held_forbidden)} training samples belong to "
                f"F_dev/F_test families, e.g. {held_forbidden[:3]}"
            )

        screened_in_train = {r.sha256 for r in self.train} & self._screened_shas
        if screened_in_train:
            raise AssertionError(
                f"LEAKAGE: {len(screened_in_train)} vault samples fingerprinted to "
                f"an F_dev/F_test family reached training, e.g. "
                f"{sorted(screened_in_train)[:3]}"
            )

        g_eval_in_train = {r.sha256 for r in self.train} & self._g_eval_shas
        if g_eval_in_train:
            raise AssertionError(
                f"LEAKAGE: {len(g_eval_in_train)} G_eval goodware samples in "
                f"training, e.g. {sorted(g_eval_in_train)[:3]}"
            )

        train_shas = {r.sha256 for r in self.train}
        for name, refs in (("val_binary", self.val_binary),
                           ("val_family", self.val_family)):
            overlap = train_shas & {r.sha256 for r in refs}
            if overlap:
                raise AssertionError(
                    f"LEAKAGE: {len(overlap)} shas in both train and {name}, "
                    f"e.g. {sorted(overlap)[:3]}"
                )

        for ref in self.train:
            if ref.family_index != FAMILY_UNLABELED:
                if not 0 <= ref.family_index < len(self.family_names):
                    raise AssertionError(
                        f"family_index {ref.family_index} out of range for "
                        f"{len(self.family_names)} classes ({ref.sha256})"
                    )

    # -- reporting -----------------------------------------------------
    def summary(self) -> dict[str, Any]:
        def counts(refs: Sequence[SampleRef]) -> dict[str, Any]:
            out: dict[str, Any] = {"n": len(refs)}
            for key in ("origin",):
                agg: dict[str, int] = {}
                for r in refs:
                    agg[getattr(r, key)] = agg.get(getattr(r, key), 0) + 1
                out[key] = agg
            out["n_malware"] = sum(1 for r in refs if r.label == 1)
            out["n_goodware"] = sum(1 for r in refs if r.label == 0)
            out["n_family_labeled"] = sum(
                1 for r in refs if r.family_index != FAMILY_UNLABELED)
            return out

        return {
            "n_family_classes": len(self.family_names),
            "family_names": self.family_names,
            "forbidden_families": sorted(self.forbidden_families),
            "train": counts(self.train),
            "val_binary": counts(self.val_binary),
            "val_family": counts(self.val_family),
            "n_vault_screened_out": len(self._screened_shas),
            "config": {
                "vault": self.config.vault,
                "vault_weight": self.config.vault_weight,
                "vault_screen": self.config.vault_screen,
                "allow_unscreened_vault": self.config.allow_unscreened_vault,
                "pe_only": self.config.pe_only,
                "include_singletons": self.config.include_singletons,
                "holdout_frac": self.config.holdout_frac,
                "seed": self.config.seed,
            },
        }


# --------------------------------------------------------------------------
# Window sampling
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class WindowSampler:
    """Samples fixed-size byte windows across the WHOLE file.

    Window-strided rather than truncated (EXP2_DESIGN §4): MalConv's classic
    first-N-bytes truncation biases the model toward headers and cannot attribute
    anything past the cut. Striding windows over the whole file removes the bias
    and gives attribution a natural granularity.

    A fresh window subset is drawn per epoch (``epoch`` seeds the draw), which
    acts as augmentation -- important with only ~12k training samples.

    Stratification divides the file into ``n_windows`` equal strata and draws one
    random offset inside each, so coverage is proportional to file layout without
    trusting the section table -- which packed samples routinely falsify.
    ``stratify="sections"`` additionally anchors windows to section offsets when
    the extraction record supplies them.
    """

    window_size: int = 262_144
    n_windows: int = 32
    stratify: str = "uniform"        # uniform | sections
    seed: int = 20260809

    def offsets(
        self,
        file_size: int,
        epoch: int = 0,
        sha256: str = "",
        sections: Sequence[dict] | None = None,
    ) -> list[int]:
        """Byte offsets to read. Deterministic given (sha, epoch)."""
        if file_size <= 0:
            return [0]
        # Whole file fits in the budget: read it all, no sampling needed.
        if file_size <= self.window_size * self.n_windows:
            return list(range(0, file_size, self.window_size))

        rng = random.Random(f"{self.seed}|{sha256}|{epoch}")
        anchors = self._section_anchors(sections, file_size) \
            if self.stratify == "sections" else []

        offsets: list[int] = []
        for anchor in anchors[: self.n_windows]:
            offsets.append(min(anchor, max(0, file_size - self.window_size)))

        remaining = self.n_windows - len(offsets)
        if remaining > 0:
            stride = file_size / remaining
            for i in range(remaining):
                lo = int(i * stride)
                hi = max(lo, min(int((i + 1) * stride), file_size) - self.window_size)
                offsets.append(rng.randint(lo, hi) if hi > lo else lo)

        return sorted(set(max(0, o) for o in offsets))

    @staticmethod
    def _section_anchors(sections: Sequence[dict] | None,
                         file_size: int) -> list[int]:
        if not sections:
            return []
        out = []
        for sec in sections:
            ptr = sec.get("raw_ptr") if isinstance(sec, dict) else None
            if ptr and 0 < ptr < file_size:
                out.append(int(ptr))
        return sorted(set(out))


def read_windows(
    path: str,
    sampler: WindowSampler,
    epoch: int = 0,
    sha256: str = "",
    sections: Sequence[dict] | None = None,
) -> list[bytes]:
    """Read the sampled windows. Static read only -- SAFETY.

    Returns an empty list on any read failure rather than raising: a single
    unreadable sample must not kill a training epoch.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    offsets = sampler.offsets(size, epoch=epoch, sha256=sha256, sections=sections)
    out: list[bytes] = []
    try:
        with open(path, "rb") as fh:
            for off in offsets:
                fh.seek(off)
                chunk = fh.read(sampler.window_size)
                if chunk:
                    out.append(chunk)
    except OSError:
        return out
    return out


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _load_json(path: str) -> dict:
    if not path:
        raise ValueError("split path is required (frozen artifacts are inputs)")
    with open(path) as fh:
        return json.load(fh)


def _read_manifest(path: str) -> Iterable[dict[str, str]]:
    """Tolerant manifest read -- it carries non-UTF-8 sample filenames."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        yield from csv.DictReader(fh)


def _screen_shas(path: str) -> set[str]:
    """Load the vault leakage screen's excluded shas.

    Accepts the artifact's ``{"exclude_sha256": {sha: {...}}}`` shape as well as a
    bare list, so a hand-built screen also works.
    """
    if not path or not os.path.exists(path):
        return set()
    with open(path) as fh:
        blob = json.load(fh)
    if isinstance(blob, list):
        return {str(s) for s in blob}
    return set(blob.get("exclude_sha256") or {})


def _collision_shas(path: str) -> set[str]:
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return {r["sha256"] for r in csv.DictReader(fh) if r.get("sha256")}


def _normalize_family(raw: str | None) -> str | None:
    """Alias-normalize a family label (Quakbot/QuakBot -- HANDOFF lesson)."""
    if not raw:
        return None
    return "".join(ch for ch in raw.lower() if ch.isalnum()) or None


def _families_by_split(malware_split: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"F_train": [], "F_dev": [], "F_test": []}
    for family, info in (malware_split.get("families") or {}).items():
        split = info.get("split")
        if split in out:
            out[split].append(family)
    return {k: sorted(v) for k, v in out.items()}


def _split_frac(refs: Sequence[SampleRef], frac: float,
                rng: random.Random) -> tuple[list[SampleRef], list[SampleRef]]:
    """Seeded split. Sorts first so the result does not depend on input order."""
    items = sorted(refs, key=lambda r: r.sha256)
    if frac <= 0 or len(items) < 2:
        return list(items), []
    n_hold = max(1, int(round(frac * len(items))))
    holdout = set(rng.sample(range(len(items)), n_hold))
    keep = [r for i, r in enumerate(items) if i not in holdout]
    held = [r for i, r in enumerate(items) if i in holdout]
    return keep, held


def _dedupe_by_sha(refs: Sequence[SampleRef]) -> list[SampleRef]:
    seen: set[str] = set()
    out: list[SampleRef] = []
    for r in refs:
        if r.sha256 not in seen:
            seen.add(r.sha256)
            out.append(r)
    return out

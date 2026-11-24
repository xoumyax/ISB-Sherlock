"""Goodware document-frequency index, built over G_stats only.

"Document frequency" = the number of goodware samples a value appears in. It is
the quantitative half of candidate hygiene: a string in 400 of 2,000 benign
files is a false-positive engine no matter how prevalent it is in the family.

**Leakage rule (EXP2_DESIGN §3, enforced here):** the index is built from
``G_stats`` records only. FP evaluation happens on ``G_eval``; an index that had
seen G_eval would be scoring against its own training data.

**Keys are case-folded and type-agnostic.** Genericity is a property of the
*value*: if ``EvilMarker`` occurs as ``evilmarker`` across 400 benign files, that
is a genericity signal regardless of which extractor slot either occurrence came
from. Case-folding is the conservative direction -- it can only make a candidate
look *more* generic, never less, so it cannot hide FP risk.
"""

from __future__ import annotations

import json
import os
import pickle
import random
from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from ..ISB.pooling import DFIndex

__all__ = ["record_values", "build_df_index", "save_df_index", "load_df_index"]


def record_values(rec: Mapping[str, Any]) -> set[str]:
    """Every case-folded value an extraction record contributes to the index.

    Covers all candidate-bearing fields, not just ASCII strings: pooling looks up
    imports, sections and PE metadata against this index too, and a DF index that
    only knew about strings would silently report ``goodware_df == 0`` for every
    import and section -- making the most generic candidates in the corpus look
    pristine.
    """
    out: set[str] = set()

    for field in ("strings_ascii", "strings_wide", "imports",
                  "import_functions", "exports"):
        for v in rec.get(field) or []:
            if v:
                out.add(str(v).lower())

    for sec in rec.get("sections") or []:
        name = sec.get("name") if isinstance(sec, dict) else sec
        if name:
            out.add(str(name).lower())

    for v in (rec.get("pe_metadata") or {}).values():
        if v:
            out.add(str(v).lower())

    for field in ("pe_original_filename", "imphash"):
        v = rec.get(field)
        if v:
            out.add(str(v).lower())

    return out


def build_df_index(
    records: Iterable[Mapping[str, Any]],
    source_of: Mapping[str, str] | None = None,
    per_source_cap: int = 600,
    min_df: int = 2,
    seed: int = 20260809,
) -> tuple[DFIndex, dict[str, Any]]:
    """Build the DF index from G_stats extraction records.

    ``per_source_cap`` keeps one large source (UCSB is 9k of the ~11k G_stats
    files) from defining "generic" on its own; sampling is seeded so the index is
    reproducible across runs and variants.

    ``min_df >= 2`` drops singletons: a value in exactly one benign file is not
    evidence of genericity, and keeping them would inflate the index by millions
    of unique strings for no signal.
    """
    records = list(records)
    source_of = source_of or {}

    # -- seeded, per-source subsample ----------------------------------
    by_source: dict[str, list[str]] = defaultdict(list)
    by_sha: dict[str, Mapping[str, Any]] = {}
    for rec in records:
        sha = rec.get("sha256")
        if not sha:
            continue
        by_sha[sha] = rec
        by_source[source_of.get(sha, "unknown")].append(sha)

    rng = random.Random(seed)
    selected: list[str] = []
    per_source_counts: dict[str, int] = {}
    for source in sorted(by_source):
        shas = sorted(by_source[source])          # sort first: order-independent
        if per_source_cap and len(shas) > per_source_cap:
            shas = rng.sample(shas, per_source_cap)
        per_source_counts[source] = len(shas)
        selected.extend(shas)

    # -- document frequency --------------------------------------------
    df: Counter[str] = Counter()
    for sha in selected:
        df.update(record_values(by_sha[sha]))

    kept = {v: c for v, c in df.items() if c >= min_df}
    index = DFIndex(df=kept, n_docs=len(selected), source="G_stats")
    meta = {
        "n_docs": len(selected),
        "n_records_available": len(by_sha),
        "per_source_counts": per_source_counts,
        "per_source_cap": per_source_cap,
        "min_df": min_df,
        "seed": seed,
        "n_values_before_min_df": len(df),
        "n_values_kept": len(kept),
        "keys": "case-folded, type-agnostic",
        "side": "G_stats only (G_eval never seen -- EXP2_DESIGN §3)",
    }
    return index, meta


def save_df_index(index: DFIndex, meta: dict[str, Any], out_dir: str,
                  basename: str = "goodware_df") -> dict[str, str]:
    """Write ``<basename>.pkl`` plus a human-readable ``<basename>.meta.json``."""
    os.makedirs(out_dir, exist_ok=True)
    pkl_path = os.path.join(out_dir, f"{basename}.pkl")
    meta_path = os.path.join(out_dir, f"{basename}.meta.json")
    with open(pkl_path, "wb") as fh:
        pickle.dump(
            {"df": dict(index.df), "n_docs": index.n_docs,
             "source": index.source, "meta": meta},
            fh, protocol=pickle.HIGHEST_PROTOCOL,
        )
    with open(meta_path, "w") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
    return {"pkl": pkl_path, "meta": meta_path}


def load_df_index(pkl_path: str) -> tuple[DFIndex, dict[str, Any]]:
    with open(pkl_path, "rb") as fh:
        blob = pickle.load(fh)
    index = DFIndex(
        df=blob["df"], n_docs=blob["n_docs"], source=blob.get("source"))
    return index, blob.get("meta", {})

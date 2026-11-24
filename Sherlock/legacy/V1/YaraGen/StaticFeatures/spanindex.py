"""Byte-span presence index over G_stats goodware.

The DF index (:mod:`dfindex`) answers "how many goodware documents *have this
value* as an extracted string / import / section name". That is an exact lookup
over whole extracted values, and it is the right question for every candidate
type the static emitter produces.

It is the wrong question for ``HEX_SPAN``. A classifier-attributed byte span is
an arbitrary *substring* of the file -- it need not coincide with any extracted
string boundary -- so no exact-key index can ever score it. Failed Approach #8
patched half of this (``trivial_hex_reason`` catches null padding); this module
is the other half.

**Why this matters, measured** (2026-08-20, njrat + guloader attribution smoke):
with only a 200-file goodware panel, 39-40% of attributed spans looked
goodware-free. Against a flavour-complete panel the survivors fell to 11.8% and
3.6%, and *every one* of the top-8 "clean" spans per family died -- guloader's
``__vbaStrMove`` hit 36 of the 42 VB6 programs in G_stats, njrat's
``.Microsoft.Vi`` hit 60 of 273 .NET ones. A span is only "absent from goodware"
with respect to the goodware you actually looked at, so this index scans the
**whole** G_stats side rather than a sample.

That is also why there is no ``per_source_cap`` here, unlike the DF index. The
cap exists there to stop one large source defining "generic" on its own -- a
*frequency* concern. Presence is zero-tolerance: dropping documents can only
invent false "clean" verdicts, never hide a real hit.

Matching is delegated to yara-python, which is the correct tool for
many-patterns-one-pass and is already a project dependency. Note this is
``yara`` (the scanner), **not** ``yaramod`` (the parser) -- this package must
stay free of yaramod and torch, and the import-purity test asserts it.

SAFETY: goodware and malware alike are read statically (``yara.match`` reads
bytes). Nothing here executes a sample.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..ISB.grammar import validate_hex_body
from ..ISB.pooling import DFIndex

__all__ = [
    "SpanIndexConfig",
    "canonical_span_key",
    "build_span_df",
    "save_span_df",
    "load_span_df",
]


def canonical_span_key(hex_body: str) -> str:
    """The index key for a hex span: lowercase, single-spaced tokens.

    ``DFIndex.count`` case-folds the probe, so keys must be stored folded or
    every lookup would miss. Token re-joining makes ``"21B8 01"`` and
    ``"21 B8 01"`` the same key, so a candidate cannot dodge the gate through
    spacing.
    """
    return " ".join(hex_body.split()).lower()


@dataclass(frozen=True)
class SpanIndexConfig:
    """Scan parameters.

    ``max_strings_per_rule`` batches the needles: yara compiles all patterns
    into one automaton, so a batch costs a single pass over the corpus. Fewer,
    larger batches are strictly faster; the cap only exists because yara has a
    per-rule string limit.
    """

    max_strings_per_rule: int = 2000
    #: Per-file yara timeout, seconds. A pathological file must not stall a scan.
    match_timeout: int = 60
    #: Report progress every N files (0 disables).
    log_every: int = 500
    #: Stop after N files; for smokes only. 0 = whole corpus.
    limit: int = 0


def _compile_batch(batch: Sequence[tuple[str, str]]):
    """Compile ``[(identifier, hex_body), ...]`` into one yara ruleset."""
    import yara  # local import: keeps module import cheap and yaramod-free

    lines = ["rule spans {", "  strings:"]
    for ident, body in batch:
        lines.append(f"    ${ident} = {{ {body} }}")
    lines.append("  condition:")
    lines.append("    any of them")
    lines.append("}")
    return yara.compile(source="\n".join(lines))


def build_span_df(
    hex_bodies: Iterable[str],
    paths: Sequence[str],
    config: SpanIndexConfig | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[DFIndex, dict[str, Any]]:
    """Count, per span, how many of ``paths`` contain it.

    Returns a :class:`DFIndex` keyed by :func:`canonical_span_key`, so it plugs
    into the same lookup surface pooling already uses for strings -- and a meta
    dict recording exactly what was scanned, because a presence verdict is only
    as trustworthy as the corpus behind it.

    Spans that are not valid YARA hex bodies are reported in
    ``meta["rejected"]`` rather than silently skipped: a span that cannot be
    compiled also cannot be gated, and pretending it scored 0 would mark it
    clean.
    """
    config = config or SpanIndexConfig()
    log = progress or (lambda _m: None)

    ident_of: dict[str, str] = {}
    body_of: dict[str, str] = {}
    rejected: dict[str, str] = {}
    for body in hex_bodies:
        key = canonical_span_key(body)
        if key in ident_of:
            continue
        verdict = validate_hex_body(body)
        if not verdict:
            rejected[key] = verdict.reason or "invalid_hex"
            continue
        ident = f"s{len(ident_of)}"
        ident_of[key] = ident
        body_of[ident] = body

    scan_paths = list(paths)
    if config.limit:
        scan_paths = scan_paths[: config.limit]

    counts: dict[str, int] = {k: 0 for k in ident_of}
    if not counts or not scan_paths:
        meta = {
            "n_spans": len(counts), "n_docs": 0, "n_rejected": len(rejected),
            "rejected": rejected, "n_unreadable": 0, "seconds": 0.0,
            "side": "G_stats only (G_eval never seen -- EXP2_DESIGN §3)",
            "per_source_cap": None,
            "note": "presence is zero-tolerance; the whole side is scanned",
        }
        return DFIndex(df=counts, n_docs=0, source="span_index"), meta

    ident_to_key = {v: k for k, v in ident_of.items()}
    batches = [
        [(ident_of[k], k) for k in list(ident_of)[i:i + config.max_strings_per_rule]]
        for i in range(0, len(ident_of), config.max_strings_per_rule)
    ]
    log(f"[spanindex] {len(counts)} spans / {len(batches)} batch(es) "
        f"over {len(scan_paths)} G_stats files")

    t0 = time.time()
    unreadable = 0
    for bi, batch in enumerate(batches):
        rules = _compile_batch(batch)
        # Per batch, one pass over the corpus. Hits are unioned per document, so
        # a span matching twice in one file still counts as one document.
        for i, path in enumerate(scan_paths):
            try:
                matches = rules.match(filepath=path, timeout=config.match_timeout)
            except Exception:
                # Unreadable / oversized / yara timeout. Counted, not fatal: a
                # goodware file we could not read is a gap in coverage, and the
                # meta records how big that gap is.
                if bi == 0:
                    unreadable += 1
                continue
            seen: set[str] = set()
            for m in matches:
                for inst in getattr(m, "strings", ()) or ():
                    ident = str(getattr(inst, "identifier", "")).lstrip("$")
                    if ident:
                        seen.add(ident)
            for ident in seen:
                key = ident_to_key.get(ident)
                if key is not None:
                    counts[key] += 1
            if config.log_every and (i + 1) % config.log_every == 0:
                log(f"[spanindex] batch {bi + 1}/{len(batches)} "
                    f"file {i + 1}/{len(scan_paths)}")

    elapsed = time.time() - t0
    n_docs = len(scan_paths) - unreadable
    meta = {
        "n_spans": len(counts),
        "n_docs": n_docs,
        "n_listed": len(scan_paths),
        "n_unreadable": unreadable,
        "n_rejected": len(rejected),
        "rejected": rejected,
        "n_spans_absent": sum(1 for v in counts.values() if v == 0),
        "seconds": round(elapsed, 1),
        "side": "G_stats only (G_eval never seen -- EXP2_DESIGN §3)",
        "per_source_cap": None,
        "note": "presence is zero-tolerance; the whole side is scanned",
    }
    log(f"[spanindex] done in {elapsed:.0f}s -- "
        f"{meta['n_spans_absent']}/{len(counts)} spans absent from goodware")
    return DFIndex(df=counts, n_docs=n_docs, source="span_index"), meta


def save_span_df(index: DFIndex, meta: Mapping[str, Any], out_dir: str,
                 stem: str = "goodware_spans") -> dict[str, str]:
    """Persist as JSON -- the keys are short and the artifact stays greppable."""
    os.makedirs(out_dir, exist_ok=True)
    idx_path = os.path.join(out_dir, f"{stem}.json")
    meta_path = os.path.join(out_dir, f"{stem}.meta.json")
    with open(idx_path, "w") as fh:
        json.dump({"n_docs": index.n_docs, "df": index.df}, fh)
    with open(meta_path, "w") as fh:
        json.dump(dict(meta), fh, indent=2)
    return {"index": idx_path, "meta": meta_path}


def load_span_df(path: str) -> DFIndex:
    with open(path) as fh:
        blob = json.load(fh)
    return DFIndex(df=blob["df"], n_docs=int(blob["n_docs"]), source="span_index")

"""Byte-presence of *any* candidate in goodware -- the FP-predictive question.

:mod:`dfindex` answers "is this value an extracted string of a goodware file?"
and :mod:`spanindex` answers the byte-substring question for hex spans. This
module is the generalisation, and it exists because of a measured failure:

A YARA rule does not match extracted strings. It matches **substrings of raw
bytes**. A candidate can be absent from every goodware file's extracted-string
set and still occur inside thousands of them -- ``Line:`` and ``.data\\x00Ic``
both scored goodware_df 0 against the DF index *and* 0 against a full
10,620-record extracted-string scan, then went into rules that matched
348 per 1,000 Win8 binaries (M4 run 95863).

So genericity for rule-building purposes must be measured the way YARA will
measure it. That is what this module does, over the whole G_stats side, with no
per-source cap -- presence is zero-tolerance, and dropping documents can only
invent false "clean" verdicts.

It is deliberately scoped to a **known needle set**: the candidates actually
under consideration. Indexing every substring of a goodware corpus is not a
thing one can do; verifying a few hundred selected candidates against it is
cheap, and that is the operating point that decides a rule's FP.

SAFETY: ``yara.match`` reads bytes. Nothing here executes a sample.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..ISB.candidate import Candidate
from ..ISB.grammar import DEFAULT_CONFIG, default_modifiers, escape_text
from ..ISB.pooling import DFIndex

__all__ = ["PresenceConfig", "build_presence_index", "presence_key"]


@dataclass(frozen=True)
class PresenceConfig:
    max_strings_per_rule: int = 2000
    match_timeout: int = 60
    log_every: int = 2000
    limit: int = 0


def presence_key(cand: Candidate) -> str:
    """Index key. Case-folded, matching the DFIndex lookup convention."""
    if cand.is_hex:
        return " ".join(cand.norm.split()).lower()
    return cand.value.lower()


def _yara_term(cand: Candidate, ident: str) -> str | None:
    """One ``strings:`` line for a candidate, or None if it cannot be one."""
    if cand.is_hex:
        body = " ".join(cand.norm.split())
        fixed = [t for t in body.split() if len(t) == 2 and "?" not in t]
        if len(fixed) < 4:
            return None
        return f"${ident} = {{ {body} }}"
    if len(cand.value) < 4:
        return None
    # Start from the modifiers the renderer will emit, so `fullword` and
    # `nocase` match the rule exactly -- checking without `fullword` would
    # reject a candidate for substring hits the rule could never make.
    mods = list(default_modifiers(cand))
    # Then widen ONE step further than the rendered form: always test both
    # encodings. Measured 2026-08-20 -- njrat's ASCII candidate
    # "WEXTRACT.EXE            .MUI" is carried by 6 G_stats files as UTF-16.
    # An ASCII-only rule genuinely will not match those files today, so a
    # render-exact check passes it; but the value is Microsoft self-extractor
    # boilerplate and is generic no matter which encoding carries it. Same
    # argument as the DF index's case folding: genericity is a property of the
    # VALUE, and widening can only make a candidate look more generic, never
    # hide FP risk. This is deliberately stricter than what we render.
    if "wide" not in mods:
        mods += ["wide", "ascii"]
    suffix = (" " + " ".join(mods)) if mods else ""
    body = escape_text(cand.value, DEFAULT_CONFIG.hex_escape_non_ascii)
    return f'${ident} = "{body}"{suffix}'


def build_presence_index(
    candidates: Iterable[Candidate],
    paths: Sequence[str],
    config: PresenceConfig | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[DFIndex, dict[str, Any]]:
    """Count, per candidate, how many of ``paths`` contain its bytes.

    Returns a :class:`DFIndex` keyed by :func:`presence_key`, so it drops into
    the same lookup surface the rest of the pipeline already uses.
    """
    import yara

    config = config or PresenceConfig()
    log = progress or (lambda _m: None)

    terms: dict[str, str] = {}          # ident -> yara line
    key_of: dict[str, str] = {}         # ident -> index key
    skipped: dict[str, str] = {}
    for cand in candidates:
        key = presence_key(cand)
        if key in key_of.values():
            continue
        ident = f"p{len(terms)}"
        line = _yara_term(cand, ident)
        if line is None:
            skipped[key] = "unrenderable_as_needle"
            continue
        terms[ident] = line
        key_of[ident] = key

    scan_paths = list(paths)[: config.limit] if config.limit else list(paths)
    counts = {k: 0 for k in key_of.values()}
    if not terms or not scan_paths:
        return (DFIndex(df=counts, n_docs=0, source="presence"),
                {"n_needles": len(counts), "n_docs": 0, "skipped": skipped})

    idents = list(terms)
    batches = [idents[i:i + config.max_strings_per_rule]
               for i in range(0, len(idents), config.max_strings_per_rule)]
    log(f"[presence] {len(terms)} needles / {len(batches)} batch(es) "
        f"over {len(scan_paths)} G_stats files")

    t0 = time.time()
    unreadable = 0
    for bi, batch in enumerate(batches):
        src = ("rule presence {\n  strings:\n"
               + "\n".join("    " + terms[i] for i in batch)
               + "\n  condition:\n    any of them\n}")
        rules = yara.compile(source=src)
        for i, path in enumerate(scan_paths):
            try:
                matches = rules.match(filepath=path,
                                      timeout=config.match_timeout)
            except Exception:                       # noqa: BLE001
                if bi == 0:
                    unreadable += 1
                continue
            seen: set[str] = set()
            for m in matches:
                for inst in getattr(m, "strings", ()) or ():
                    ident = str(getattr(inst, "identifier", "")).lstrip("$")
                    if ident in key_of:
                        seen.add(ident)
            for ident in seen:
                counts[key_of[ident]] += 1
            if config.log_every and (i + 1) % config.log_every == 0:
                log(f"[presence] batch {bi + 1}/{len(batches)} "
                    f"file {i + 1}/{len(scan_paths)}")

    n_docs = len(scan_paths) - unreadable
    meta = {
        "n_needles": len(counts), "n_docs": n_docs,
        "n_absent": sum(1 for v in counts.values() if v == 0),
        "n_skipped": len(skipped), "skipped": skipped,
        "n_unreadable": unreadable,
        "seconds": round(time.time() - t0, 1),
        "per_source_cap": None,
        "note": ("byte-substring presence, the question YARA actually asks; "
                 "extracted-string DF is not FP-predictive"),
    }
    log(f"[presence] done in {meta['seconds']:.0f}s -- "
        f"{meta['n_absent']}/{len(counts)} candidates absent from goodware")
    return DFIndex(df=counts, n_docs=n_docs, source="presence"), meta

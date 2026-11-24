"""Extraction record -> ``Candidate`` list (the ``static`` candidate source).

This is the ``static_only`` arm of the candidate-source ablation
(EXP2_DESIGN §5): everything obtainable without the classifier. The classifier's
attributed candidates (M2) are emitted separately and unioned later, which is
what makes "what is discovery worth?" a measurable quantity.

Layering is deliberate and must not be collapsed: **emit -> stoplist -> grammar**.
Emission is generous; the stoplist removes known-generic values with an auditable
reason; the grammar filter removes what cannot be rendered. Folding hygiene into
emission would make the ``all`` arm dishonest -- it is supposed to show what
happens with no selection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..ISB.candidate import Candidate, CType, dedupe

__all__ = ["EmitConfig", "record_to_candidates", "records_to_candidates"]


@dataclass(frozen=True)
class EmitConfig:
    """Which v1 emitters run (EXP2_DESIGN §5). v2 items stay off."""

    strings: bool = True
    imports: bool = True
    import_functions: bool = True
    exports: bool = True
    sections: bool = True
    pe_metadata: bool = True
    imphash: bool = True
    #: Emission-time floor only; expressibility has its own in ISB/grammar.py.
    min_len: int = 4
    #: Skip section names that are pure padding/garbage bytes.
    max_len: int = 512
    source_tag: str = "static"


def _ok(value: Any, config: EmitConfig) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    return bool(v) and config.min_len <= len(v) <= config.max_len


def record_to_candidates(
    rec: Mapping[str, Any], config: EmitConfig | None = None
) -> list[Candidate]:
    """Emit every static candidate from one extraction record.

    Tolerant of partial records: a sample whose PE parse failed still yields its
    strings, which is exactly why :func:`~YaraGen.StaticFeatures.extract
    .extract_record` returns partial records instead of raising.
    """
    config = config or EmitConfig()
    out: list[Candidate] = []
    src = config.source_tag

    def add(value: Any, ctype: str) -> None:
        if _ok(value, config):
            out.append(Candidate(value=value.strip(), ctype=ctype, source=src))

    if config.strings:
        for v in rec.get("strings_ascii") or []:
            add(v, CType.STRING_ASCII)
        for v in rec.get("strings_wide") or []:
            add(v, CType.STRING_WIDE)

    if config.imports:
        for v in rec.get("imports") or []:
            add(v, CType.IMPORT)
    if config.import_functions:
        # API names share the IMPORT type: both answer "what does this binary
        # link against", and the stoplist's universal-import list is API names.
        for v in rec.get("import_functions") or []:
            add(v, CType.IMPORT)

    if config.exports:
        for v in rec.get("exports") or []:
            add(v, CType.EXPORT)

    if config.sections:
        for sec in rec.get("sections") or []:
            name = sec.get("name") if isinstance(sec, dict) else sec
            add(name, CType.PE_SECTION)

    if config.pe_metadata:
        meta = rec.get("pe_metadata") or {}
        # OriginalFilename gets its own type: the top detection carrier in the
        # pre-wipe diagnosis (0.75), so it must be distinguishable downstream.
        add(rec.get("pe_original_filename") or meta.get("OriginalFilename"),
            CType.PE_ORIGINAL_FILENAME)
        for key, value in meta.items():
            if key == "OriginalFilename":
                continue
            add(value, CType.PE_METADATA)

    if config.imphash:
        add(rec.get("imphash"), CType.HASH_IMPHASH)

    return dedupe(out)


def records_to_candidates(
    records: Iterable[Mapping[str, Any]], config: EmitConfig | None = None
) -> dict[str, list[Candidate]]:
    """Per-sha candidate sets, ready for ``FamilyCandidateSet.add_sample``."""
    config = config or EmitConfig()
    out: dict[str, list[Candidate]] = {}
    for rec in records:
        sha = rec.get("sha256")
        if sha:
            out[sha] = record_to_candidates(rec, config)
    return out

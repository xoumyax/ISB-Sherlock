"""L1: the render form and the match form stay separate.

The lesson (measured in V1, 2026): writing the match form into a rule produced
rules that could not match their own sample. In Sherlock's IR the render form is
``value`` and ``qualifier``, exactly as observed; ``match_key()`` is derived, never
stored and never rendered. ``PE_IMPORT`` is the kind where the two differ (YARA
compares DLL names case-insensitively), so it carries the test; every other kind is
checked to render exactly what was observed.
"""

from __future__ import annotations

from pathlib import Path

from sherlock.core.ir import (
    Candidate,
    Kind,
    read_candidates_jsonl,
    write_candidates_jsonl,
)


def _observed() -> list[Candidate]:
    return [
        Candidate(Kind.PE_IMPORT, "GetProcAddress", qualifier="KERNEL32.dll"),
        Candidate(Kind.TEXT, "Mixed Case ", encoding="ascii"),
        Candidate(Kind.TEXT, "Wide Text", encoding="wide"),
        Candidate.from_bytes(b"MZ"),
        Candidate(Kind.PE_SECTION_NAME, ".TEXT"),
        Candidate(Kind.PE_IMPHASH, "f34d5f2d4577ed6d9ceec516c1f5a744"),
    ]


def test_render_never_uses_norm(tmp_path: Path) -> None:
    imp = _observed()[0]
    _, _, qual_match, _ = imp.match_key()
    assert qual_match == "kernel32.dll"
    assert imp.qualifier == "KERNEL32.dll"  # render form untouched by the match form

    path = tmp_path / "l1.jsonl"
    write_candidates_jsonl(path, _observed())
    text = path.read_text()
    assert "kernel32.dll" not in text  # the match form is never stored
    back, dropped = read_candidates_jsonl(path)
    assert dropped == {}
    assert [(c.qualifier, c.value) for c in back] == [
        (c.qualifier, c.value) for c in _observed()
    ]
    assert back[0].qualifier == "KERNEL32.dll"

"""Unit tests for ``sherlock.core.ir`` (redesigned 23 Nov; design: G0.md §2a).

Round-trips compare ``to_dict()``, not ``==``: equality is on the match key by
design, so ``==`` would pass even if a round-trip lost occurrences or meta.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sherlock.core.ir import (
    ENCODINGS,
    KINDS,
    Candidate,
    Kind,
    Occurrence,
    read_candidates_jsonl,
    write_candidates_jsonl,
)

SHA_A = "a" * 64
SHA_B = "0123456789abcdef" * 4
IMPHASH = "f34d5f2d4577ed6d9ceec516c1f5a744"


# -- kinds --------------------------------------------------------------------


def test_kinds_are_plain_strings() -> None:
    assert Kind.TEXT == "TEXT"
    assert KINDS == {
        "TEXT",
        "BYTES",
        "PE_IMPORT",
        "PE_SECTION_NAME",
        "PE_IMPHASH",
    }
    assert ENCODINGS == {"ascii", "wide"}


def test_unknown_kind_raises() -> None:
    with pytest.raises(ValueError, match="kind"):
        Candidate(kind="STRING_ASCII", value="x")


# -- TEXT ---------------------------------------------------------------------


def test_text_kept_exactly() -> None:
    c = Candidate(Kind.TEXT, "  Mixed Case\t", encoding="ascii")
    assert c.value == "  Mixed Case\t"
    assert c.match_key() == (Kind.TEXT, "ascii", None, "  Mixed Case\t")


def test_text_needs_an_encoding_and_others_refuse_one() -> None:
    with pytest.raises(ValueError, match="encoding"):
        Candidate(Kind.TEXT, "x")
    with pytest.raises(ValueError, match="encoding"):
        Candidate(Kind.TEXT, "x", encoding="utf8")
    with pytest.raises(ValueError, match="encoding"):
        Candidate(Kind.PE_SECTION_NAME, ".text", encoding="ascii")


@pytest.mark.parametrize("enc", ["ascii", "wide"])
@pytest.mark.parametrize("bad", ["caf\u00e9", "\ud800", "\U0001f600"])
def test_text_must_be_ascii_in_both_encodings(enc: str, bad: str) -> None:
    # YARA's ``wide`` interleaves zero bytes with the rule's bytes; it is not
    # UTF-16, so non-ASCII "wide" text would render a rule that misses its sample.
    with pytest.raises(ValueError, match="ASCII"):
        Candidate(Kind.TEXT, bad, encoding=enc)


def test_ascii_and_wide_are_distinct() -> None:
    a = Candidate(Kind.TEXT, "evil", encoding="ascii")
    w = Candidate(Kind.TEXT, "evil", encoding="wide")
    assert a != w


def test_text_case_is_not_folded() -> None:
    assert Candidate(Kind.TEXT, "Evil", encoding="ascii") != Candidate(
        Kind.TEXT, "evil", encoding="ascii"
    )


def test_empty_text_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        Candidate(Kind.TEXT, "", encoding="ascii")


# -- BYTES --------------------------------------------------------------------


def test_bytes_from_bytes_and_length() -> None:
    c = Candidate.from_bytes(b"MZ\x90\x00")
    assert c.kind == Kind.BYTES
    assert c.value == "4d5a9000"
    assert c.n_bytes == 4
    assert c.to_bytes() == b"MZ\x90\x00"


@pytest.mark.parametrize("bad", ["4D5A", "4d5", "4d 5a", "zz", "4d??", ""])
def test_bytes_must_be_canonical_hex(bad: str) -> None:
    with pytest.raises(ValueError, match="BYTES"):
        Candidate(Kind.BYTES, bad)


def test_n_bytes_only_for_bytes() -> None:
    with pytest.raises(ValueError, match="BYTES"):
        _ = Candidate(Kind.PE_SECTION_NAME, ".text").n_bytes


# -- PE kinds -----------------------------------------------------------------


def test_import_render_exact_match_folds_dll_only() -> None:
    c = Candidate(Kind.PE_IMPORT, "GetProcAddress", qualifier="KERNEL32.dll")
    assert (c.qualifier, c.value) == ("KERNEL32.dll", "GetProcAddress")
    assert c.match_key() == (Kind.PE_IMPORT, None, "kernel32.dll", "GetProcAddress")
    same = Candidate(Kind.PE_IMPORT, "GetProcAddress", qualifier="kernel32.DLL")
    other_fn = Candidate(Kind.PE_IMPORT, "getprocaddress", qualifier="KERNEL32.dll")
    assert c == same and hash(c) == hash(same)
    assert c != other_fn


def test_import_needs_qualifier_and_others_refuse_one() -> None:
    with pytest.raises(ValueError, match="qualifier"):
        Candidate(Kind.PE_IMPORT, "GetProcAddress")
    with pytest.raises(ValueError, match="qualifier"):
        Candidate(Kind.PE_IMPORT, "GetProcAddress", qualifier="")
    with pytest.raises(ValueError, match="qualifier"):
        Candidate(Kind.PE_SECTION_NAME, ".text", qualifier="x")


def test_dll_fold_is_ascii_only() -> None:
    kelvin = Candidate(Kind.PE_IMPORT, "f", qualifier="\u212a.dll")  # KELVIN SIGN
    plain = Candidate(Kind.PE_IMPORT, "f", qualifier="k.dll")
    assert kelvin != plain
    assert kelvin.match_key()[2] == "\u212a.dll"


def test_section_name_exact() -> None:
    assert Candidate(Kind.PE_SECTION_NAME, ".TEXT") != Candidate(
        Kind.PE_SECTION_NAME, ".text"
    )


@pytest.mark.parametrize(
    "bad", [IMPHASH.upper(), IMPHASH[:-1], "x" * 32, IMPHASH + " "]
)
def test_imphash_strict(bad: str) -> None:
    with pytest.raises(ValueError, match="PE_IMPHASH"):
        Candidate(Kind.PE_IMPHASH, bad)
    assert Candidate(Kind.PE_IMPHASH, IMPHASH).value == IMPHASH


@pytest.mark.parametrize("kind", ["PE_IMPORT", "PE_SECTION_NAME"])
def test_empty_value_raises(kind: str) -> None:
    q = "x.dll" if kind == Kind.PE_IMPORT else None
    with pytest.raises(ValueError, match="empty"):
        Candidate(kind, "", qualifier=q)


# -- occurrence ---------------------------------------------------------------


def test_occurrence_round_trip_and_validation() -> None:
    occ = Occurrence(sha256=SHA_A, section=".text", offset=1024)
    assert Occurrence.from_dict(occ.to_dict()) == occ
    with pytest.raises(ValueError, match="sha256"):
        Occurrence(sha256=SHA_A.upper())
    with pytest.raises(ValueError, match="offset"):
        Occurrence(SHA_A, offset=-1)
    with pytest.raises(ValueError, match="offset"):
        Occurrence(SHA_A, offset=True)
    with pytest.raises(ValueError, match="section"):
        Occurrence(SHA_A, section=3)  # type: ignore[arg-type]


def test_with_occurrences_and_samples() -> None:
    c = Candidate(Kind.PE_IMPHASH, IMPHASH, occurrences=(Occurrence(SHA_A),))
    m = c.with_occurrences([Occurrence(SHA_B, ".data", 2), Occurrence(SHA_A)])
    assert m.occurrences == (Occurrence(SHA_A), Occurrence(SHA_B, ".data", 2))
    assert m.samples() == (SHA_A, SHA_B)
    assert c.occurrences == (Occurrence(SHA_A),)


def test_occurrences_must_be_occurrence_objects() -> None:
    with pytest.raises(ValueError, match="occurrences"):
        Candidate(Kind.PE_IMPHASH, IMPHASH, occurrences=("x",))  # type: ignore[arg-type]


# -- meta, dict and JSONL -----------------------------------------------------


def test_occurrences_generator_and_non_iterable() -> None:
    occ = Occurrence(SHA_A)
    c = Candidate(Kind.PE_IMPHASH, IMPHASH, occurrences=(o for o in [occ]))  # type: ignore[arg-type]
    assert c.occurrences == (occ,)
    for bad in (5, None):
        with pytest.raises(ValueError, match="occurrences"):
            Candidate(Kind.PE_IMPHASH, IMPHASH, occurrences=bad)  # type: ignore[arg-type]


def test_meta_is_copied_at_construction() -> None:
    m: dict[str, object] = {"a": 1}
    c = Candidate(Kind.PE_IMPHASH, IMPHASH, meta=m)
    m["b"] = float("nan")
    assert c.meta == {"a": 1}


def test_empty_source_raises() -> None:
    with pytest.raises(ValueError, match="source"):
        Candidate(Kind.PE_IMPHASH, IMPHASH, source="")


def test_meta_scalars_only() -> None:
    Candidate(Kind.PE_IMPHASH, IMPHASH, meta={"a": 1, "b": None, "c": 0.5, "d": "x"})
    with pytest.raises(ValueError, match="meta"):
        Candidate(Kind.PE_IMPHASH, IMPHASH, meta={"a": [1]})
    with pytest.raises(ValueError, match="meta"):
        Candidate(Kind.PE_IMPHASH, IMPHASH, meta={"a": float("nan")})


def _sample() -> list[Candidate]:
    return [
        Candidate(
            Kind.TEXT,
            "cafe \x00\x7f",
            encoding="wide",
            occurrences=(Occurrence(SHA_A, ".rdata", 7),),
            source="extract.test",
            meta={"n": 3},
        ),
        Candidate(Kind.TEXT, "C:\\Users\\x", encoding="ascii"),
        Candidate.from_bytes(b"\x00\xff"),
        Candidate(Kind.PE_IMPORT, "LoadLibraryA", qualifier="KERNEL32.dll"),
        Candidate(Kind.PE_SECTION_NAME, ".UPX0"),
        Candidate(Kind.PE_IMPHASH, IMPHASH, occurrences=(Occurrence(SHA_B),)),
    ]


def test_dict_round_trip_is_lossless() -> None:
    for c in _sample():
        d = c.to_dict()
        assert set(d) == {
            "kind",
            "value",
            "qualifier",
            "encoding",
            "occurrences",
            "source",
            "meta",
        }
        assert Candidate.from_dict(json.loads(json.dumps(d))).to_dict() == d


def test_jsonl_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    assert write_candidates_jsonl(path, _sample()) == 6
    back, dropped = read_candidates_jsonl(path)
    assert dropped == {}
    assert [c.to_dict() for c in back] == [c.to_dict() for c in _sample()]


@pytest.mark.parametrize(
    "record",
    [
        {"kind": "TEXT", "value": "x"},  # no encoding
        {"kind": 5, "value": "x"},
        {"kind": "BYTES", "value": 5},
        {"kind": "NOPE", "value": "x"},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "occurrences": [{"sha256": 1}]},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "occurrences": "abc"},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "meta": {"x": {}}},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "occurrences": ""},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "occurrences": {}},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "occurrences": 0},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "meta": 0},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "meta": [["a", 1]]},
        {"kind": "PE_IMPHASH", "value": IMPHASH, "qualifer": "x"},
        {
            "kind": "PE_IMPHASH",
            "value": IMPHASH,
            "occurrences": [{"sha256": SHA_A, "ofset": 1}],
        },
        {"kind": "PE_IMPHASH", "value": IMPHASH, "occurrences": [[SHA_A]]},
        ["not", "a", "dict"],
    ],
)
def test_jsonl_bad_records_dropped_not_crashing(tmp_path: Path, record: object) -> None:
    path = tmp_path / "c.jsonl"
    good = Candidate(Kind.PE_IMPHASH, IMPHASH).to_dict()
    path.write_text(json.dumps(good) + "\n{bad json\n" + json.dumps(record) + "\n\n")
    back, dropped = read_candidates_jsonl(path)
    assert [c.value for c in back] == [IMPHASH]
    assert dropped == {"bad_json": [2], "bad_record": [3]}


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe{}", b"1" * 5000, b"[" * 100_000 + b"]" * 100_000],
    ids=["not_utf8", "huge_int", "deep_nesting"],
)
def test_jsonl_hostile_lines_dropped(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "c.jsonl"
    good = json.dumps(Candidate(Kind.PE_IMPHASH, IMPHASH).to_dict()).encode()
    path.write_bytes(good + b"\n" + raw + b"\n" + good + b"\n")
    back, dropped = read_candidates_jsonl(path)
    assert len(back) == 2
    assert dropped == {"bad_json": [2]}

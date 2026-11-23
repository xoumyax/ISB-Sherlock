"""M0 tests: YaraGen/ISB shared core (candidate IR, grammar, pooling, stoplist).

No real corpora, no real artifacts, no filesystem writes outside tmp_path.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from YaraGen.ISB import (  # noqa: E402
    DFIndex,
    Candidate,
    CType,
    FamilyCandidateSet,
    GrammarConfig,
    RenderKind,
    Stoplist,
    build_xfam_index,
    canonical_ctype,
    dedupe,
    escape_text,
    expressible,
    filter_expressible,
    normalize_value,
    pool_families,
    refang,
    render_kind,
    render_module_term,
    render_string,
    repair_split_hash,
    required_modules,
    safe_identifier,
    sanitize_rule_name,
    validate_hex_body,
    validate_modifiers,
    value_entropy,
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


# ==========================================================================
# Candidate IR: type space and aliases
# ==========================================================================

def test_canonical_ctype_aliases_unify_spellings():
    # SECTION_NAME (EXP2 doc) and PE_SECTION (EXP1 doc) are the same concept;
    # pooling must not split them.
    assert canonical_ctype("SECTION_NAME") == CType.PE_SECTION
    assert canonical_ctype("PE_SECTION") == CType.PE_SECTION
    assert canonical_ctype("IMPHASH") == CType.HASH_IMPHASH
    assert canonical_ctype("PE_IMPORT_DLL") == CType.IMPORT
    assert canonical_ctype("  domain  ") == CType.DOMAIN


def test_unknown_type_passes_through_but_is_not_expressible():
    c = Candidate(value="CVE-2021-44228", ctype="CVE")
    assert c.ctype == "CVE"
    verdict = expressible(c)
    assert not verdict
    assert verdict.reason == "unknown_type"


def test_from_ioc_strict_rejects_out_of_space_type():
    with pytest.raises(ValueError):
        Candidate.from_ioc("x" * 8, "HASH_SSDEEP", strict=True)
    # permissive default does not raise
    assert Candidate.from_ioc("x" * 8, "HASH_SSDEEP").ctype == "HASH_SSDEEP"


def test_section_name_and_pe_section_share_one_key():
    a = Candidate(value="UPX0", ctype="SECTION_NAME", source="pefile")
    b = Candidate(value="upx0", ctype="PE_SECTION", source="ner")
    assert a.key() == b.key()
    assert a == b
    assert len({a, b}) == 1


# ==========================================================================
# Candidate IR: normalization (render form vs match form)
# ==========================================================================

def test_defang_reversal():
    assert refang("hxxp://evil[.]com/a") == "http://evil.com/a"
    assert refang("hxxps://evil(dot)com") == "https://evil.com"
    assert refang("bad[.]actor[.]net") == "bad.actor.net"
    assert refang("user[at]evil[.]com") == "user@evil.com"
    assert refang("10.0.0.1[:]8080") == "10.0.0.1:8080"


def test_split_hash_repair_only_on_exact_length():
    wrapped = "e3b0c44298fc1c14 9afbf4c8996fb924 27ae41e4649b934c a495991b7852b855"
    assert repair_split_hash(wrapped, CType.HASH_SHA256) == SHA256
    # An inexact rejoin would fabricate a hash that never appeared: refuse.
    truncated = "e3b0c44298fc1c14 9afbf4c8996fb924"
    assert repair_split_hash(truncated, CType.HASH_SHA256) == truncated
    # Non-hex content is left alone.
    assert repair_split_hash("evil corp", CType.HASH_SHA256) == "evil corp"


def test_split_hash_repair_type_agnostic_fallback():
    wrapped_md5 = "d41d8cd98f00b204 e9800998ecf8427e"
    assert repair_split_hash(wrapped_md5) == MD5


def test_hash_norm_is_lowercase_and_render_is_whitespace_free():
    c = Candidate(value="E3B0C44298FC1C14 9AFBF4C8996FB924"
                        "27AE41E4649B934C A495991B7852B855",
                  ctype=CType.HASH_SHA256)
    assert c.value == SHA256.upper()
    assert c.norm == SHA256


def test_render_form_preserves_case_but_norm_folds_it():
    # Rendering the folded form would produce a rule that cannot match the
    # real sample -- the two forms must stay distinct.
    c = Candidate(value="C:\\Users\\Public\\Evil.EXE", ctype=CType.FILE_PATH)
    assert c.value == "C:\\Users\\Public\\Evil.EXE"
    assert c.norm == "c:\\users\\public\\evil.exe"


def test_case_sensitive_types_keep_case_in_norm():
    a = Candidate(value="EvilString", ctype=CType.STRING_ASCII)
    b = Candidate(value="evilstring", ctype=CType.STRING_ASCII)
    assert a.norm == "EvilString"
    assert a != b


def test_registry_path_separator_normalization():
    a = Candidate(value="HKCU\\Software\\Evil", ctype=CType.REGISTRY_KEY)
    b = Candidate(value="HKCU\\\\Software\\\\Evil", ctype=CType.REGISTRY_KEY)
    assert a.norm == b.norm == "hkcu\\software\\evil"


def test_hex_canonicalization_forms():
    compact = Candidate(value="e2 34 ?? c8", ctype=CType.YARA_HEX)
    braced = Candidate(value="{ E2 34 ?? C8 }", ctype=CType.HEX_SPAN)
    glued = Candidate(value="E234??C8", ctype=CType.HEX_SPAN)
    assert compact.norm == "E2 34 ?? C8"
    assert braced.norm == "E2 34 ?? C8"
    assert glued.norm == "E2 34 ?? C8"


def test_hex_jump_and_alternative_canonicalization():
    jump = Candidate(value="{ F4 23 [ 4 - 6 ] 62 B4 }", ctype=CType.HEX_SPAN)
    assert jump.norm == "F4 23 [4-6] 62 B4"
    alt = Candidate(value="{ F4 23 ( 62 B4 | 56 ) 45 }", ctype=CType.HEX_SPAN)
    assert alt.norm == "F4 23 (62 B4 | 56) 45"


def test_printable_len_counts_fixed_hex_bytes_only():
    c = Candidate(value="{ E2 34 ?? C8 [2-4] AB }", ctype=CType.HEX_SPAN)
    assert c.printable_len == 4  # E2 34 C8 AB; wildcard and jump excluded


def test_url_defang_and_ip_normalization_via_candidate():
    u = Candidate(value=" hxxps://bad[.]example[.]com/p ", ctype=CType.URL)
    assert u.value == "https://bad.example.com/p"
    ip = Candidate(value="185.0.0[.]9", ctype="IPV4")
    assert ip.ctype == CType.IP_ADDRESS
    assert ip.norm == "185.0.0.9"


def test_normalize_value_is_pure_function():
    assert normalize_value("EVIL.COM", CType.DOMAIN) == "evil.com"
    assert normalize_value("EVIL.COM", CType.STRING_ASCII) == "EVIL.COM"


# ==========================================================================
# Candidate IR: identity and round-trip
# ==========================================================================

def test_to_dict_from_dict_round_trip():
    c = Candidate(value="evil.com", ctype=CType.DOMAIN, source="ner_v13m",
                  attrs={"attribution_bin": 0.5, "offset": 12})
    back = Candidate.from_dict(c.to_dict())
    assert back == c
    assert back.to_dict() == c.to_dict()
    assert back.attrs["attribution_bin"] == 0.5


def test_attrs_do_not_affect_identity():
    a = Candidate(value="evil.com", ctype=CType.DOMAIN, attrs={"score": 1.0})
    b = Candidate(value="evil.com", ctype=CType.DOMAIN, attrs={"score": 9.9})
    assert a == b and hash(a) == hash(b)


def test_encoding_participates_in_identity():
    a = Candidate(value="Mutex1234", ctype=CType.STRING_ASCII)
    b = Candidate(value="Mutex1234", ctype=CType.STRING_WIDE)
    assert b.encoding == "wide"
    assert a != b


def test_dedupe_is_stable_first_wins():
    cands = [
        Candidate(value="evil.com", ctype=CType.DOMAIN, source="first"),
        Candidate(value="EVIL.com", ctype=CType.DOMAIN, source="second"),
        Candidate(value="other.com", ctype=CType.DOMAIN),
    ]
    out = dedupe(cands)
    assert len(out) == 2
    assert out[0].source == "first"


def test_candidate_is_immutable():
    c = Candidate(value="evil.com", ctype=CType.DOMAIN)
    with pytest.raises(Exception):
        c.value = "other.com"  # type: ignore[misc]


# ==========================================================================
# Grammar: render kinds
# ==========================================================================

def test_hashes_render_as_module_terms_not_strings():
    # A file hash is a property of the file, not bytes inside it.
    assert render_kind(CType.HASH_SHA256) == RenderKind.MODULE
    assert render_kind(CType.HASH_IMPHASH) == RenderKind.MODULE
    assert render_kind(CType.STRING_ASCII) == RenderKind.STRING
    assert render_kind("NOPE") == RenderKind.NONE


def test_render_module_term_per_hash_type():
    sha = Candidate(value=SHA256.upper(), ctype=CType.HASH_SHA256)
    assert render_module_term(sha) == f'hash.sha256(0, filesize) == "{SHA256}"'
    md5 = Candidate(value=MD5, ctype=CType.HASH_MD5)
    assert render_module_term(md5) == f'hash.md5(0, filesize) == "{MD5}"'
    imp = Candidate(value=MD5.upper(), ctype="IMPHASH")
    assert render_module_term(imp) == f'pe.imphash() == "{MD5}"'


def test_required_modules_collected():
    cands = [
        Candidate(value=SHA256, ctype=CType.HASH_SHA256),
        Candidate(value=MD5, ctype="IMPHASH"),
        Candidate(value="evilstring", ctype=CType.STRING_ASCII),
    ]
    assert required_modules(cands) == ["hash", "pe"]
    assert required_modules([cands[2]]) == []


def test_render_kind_mismatch_raises():
    sha = Candidate(value=SHA256, ctype=CType.HASH_SHA256)
    with pytest.raises(ValueError):
        render_string(sha, "$h")
    s = Candidate(value="evilstring", ctype=CType.STRING_ASCII)
    with pytest.raises(ValueError):
        render_module_term(s)


def test_malformed_hash_is_not_expressible():
    short = Candidate(value="abcdef", ctype=CType.HASH_SHA256)
    v = expressible(short)
    assert not v and v.reason.startswith("hash_wrong_length")
    nonhex = Candidate(value="z" * 64, ctype=CType.HASH_SHA256)
    assert expressible(nonhex).reason == "hash_not_hex"


# ==========================================================================
# Grammar: text strings, escaping, identifiers, modifiers
# ==========================================================================

def test_escape_text_handles_backslash_and_quote_without_double_escaping():
    assert escape_text('a\\b"c') == 'a\\\\b\\"c'
    assert escape_text("line\nnext\ttab\r") == "line\\nnext\\ttab\\r"


def test_escape_text_hex_escapes_non_printable_and_unicode():
    assert escape_text("a\x00b") == "a\\x00b"
    # Typographic quote from a PDF becomes explicit bytes, not a parse error.
    assert "\\x" in escape_text("evil\u2019s tool")


def test_render_string_text_with_default_modifiers():
    d = Candidate(value="Evil.Example.COM", ctype=CType.DOMAIN)
    line = render_string(d, "$d0")
    assert line == '$d0 = "Evil.Example.COM" nocase'
    w = Candidate(value="MutexName", ctype=CType.STRING_WIDE)
    assert render_string(w, "$w0") == '$w0 = "MutexName" wide ascii'
    a = Candidate(value="EvilPayload", ctype=CType.STRING_ASCII)
    assert render_string(a, "$s0") == '$s0 = "EvilPayload"'


def test_render_string_hex_uses_brace_form():
    h = Candidate(value="E2 34 ?? C8 AB CD", ctype=CType.HEX_SPAN)
    assert render_string(h, "$h0") == "$h0 = { E2 34 ?? C8 AB CD }"


def test_safe_identifier_and_rule_name_legality():
    assert safe_identifier("evil.com", 0) == "$evil_com0"
    assert safe_identifier("9lives") == "$s9lives"
    assert safe_identifier("condition") == "$condition_"
    assert sanitize_rule_name("Agent Tesla / v2") == "Agent_Tesla___v2"
    assert sanitize_rule_name("2020rule").startswith("r_")
    assert sanitize_rule_name("rule") == "rule_rule"


def test_validate_modifiers_matrix():
    assert validate_modifiers(["wide", "ascii", "nocase"])
    assert validate_modifiers(["fullword", "nocase"])
    bad = validate_modifiers(["nocase", "xor"])
    assert not bad and bad.reason.startswith("modifier_conflict")
    assert not validate_modifiers(["base64", "fullword"])
    assert not validate_modifiers(["nocase"], "hex")
    assert not validate_modifiers(["xor"], "regex")
    assert not validate_modifiers(["bogus"])


def test_render_string_rejects_illegal_explicit_modifiers():
    c = Candidate(value="EvilPayload", ctype=CType.STRING_ASCII)
    with pytest.raises(ValueError):
        render_string(c, "$s0", modifiers=["nocase", "xor"])


# ==========================================================================
# Grammar: hex validation
# ==========================================================================

def test_hex_body_accepts_documented_constructions():
    assert validate_hex_body("E2 34 ?? C8 A? FB")
    assert validate_hex_body("F4 23 ~00 62 B4")
    assert validate_hex_body("F4 23 [4-6] 62 B4")
    assert validate_hex_body("F4 23 [4-] 62 B4")
    assert validate_hex_body("F4 23 (62 B4 | 56 78) 45 AB")


def test_hex_body_rejects_jump_at_the_edges():
    v = validate_hex_body("[4-6] 62 B4 AB CD")
    assert not v and v.reason == "hex_jump_at_edge"
    assert validate_hex_body("62 B4 AB CD [4-6]").reason == "hex_jump_at_edge"


def test_hex_body_rejects_reversed_jump_and_bad_tokens():
    assert validate_hex_body("AB CD [6-4] EF 12").reason == "hex_jump_reversed"
    assert validate_hex_body("AB CD ZZ EF").reason.startswith("hex_bad_token")
    assert validate_hex_body("").reason == "hex_empty"


def test_hex_body_rejects_unbalanced_group():
    assert validate_hex_body("AB CD (EF | 12").reason == "hex_unbalanced_group"


def test_hex_body_enforces_minimum_fixed_bytes():
    v = validate_hex_body("AB ?? ??")
    assert not v and v.reason.startswith("hex_too_few_fixed_bytes")
    loose = GrammarConfig(min_hex_fixed_bytes=1)
    assert validate_hex_body("AB ?? ??", loose)


# ==========================================================================
# Grammar: expressibility filter
# ==========================================================================

def test_expressibility_length_and_atom_rules():
    assert not expressible(Candidate(value="ab", ctype=CType.STRING_ASCII))
    assert expressible(Candidate(value="abcd", ctype=CType.STRING_ASCII))
    long_v = Candidate(value="a" * 1000, ctype=CType.STRING_ASCII)
    assert expressible(long_v).reason.startswith("too_long")
    ws = Candidate(value="   \t  ", ctype=CType.STRING_ASCII)
    assert not expressible(ws)


def test_short_section_names_survive_the_default_min_length():
    # ".text"/"UPX0" must reach the stoplist rather than being length-filtered;
    # that is where they are supposed to die, with an auditable reason.
    assert expressible(Candidate(value="UPX0", ctype=CType.PE_SECTION))
    assert expressible(Candidate(value=".text", ctype=CType.PE_SECTION))


def test_filter_expressible_buckets_rejections_by_reason():
    cands = [
        Candidate(value="evil.example.com", ctype=CType.DOMAIN),
        Candidate(value="ab", ctype=CType.STRING_ASCII),
        Candidate(value="CVE-2021-1234", ctype="CVE"),
        Candidate(value=SHA256, ctype=CType.HASH_SHA256),
    ]
    kept, dropped = filter_expressible(cands)
    assert len(kept) == 2
    assert set(dropped) == {"too_short:2", "unknown_type"}


def test_grammar_config_can_tighten_min_length():
    strict = GrammarConfig(min_string_len=8)
    assert not expressible(Candidate(value="UPX0", ctype=CType.PE_SECTION), strict)


# ==========================================================================
# Pooling: support statistics
# ==========================================================================

def _c(v, t=CType.STRING_ASCII, **attrs):
    return Candidate(value=v, ctype=t, source="test", attrs=attrs)


def _family(name="agenttesla"):
    fcs = FamilyCandidateSet(name)
    fcs.add_sample("sha_a", [_c("AlphaMarker"), _c("SharedMarker"), _c("kernel32.dll")])
    fcs.add_sample("sha_b", [_c("BetaMarker"), _c("SharedMarker"), _c("kernel32.dll")])
    fcs.add_sample("sha_c", [_c("SharedMarker"), _c("kernel32.dll")])
    fcs.add_sample("sha_d", [_c("kernel32.dll")])
    return fcs


def test_prevalence_math():
    fcs = _family()
    pooled = {p.candidate.value: p for p in fcs.pool()}
    assert fcs.n_samples == 4
    assert pooled["kernel32.dll"].n_containing == 4
    assert pooled["kernel32.dll"].prevalence == 1.0
    assert pooled["SharedMarker"].prevalence == 0.75
    assert pooled["AlphaMarker"].prevalence == 0.25


def test_re_adding_a_sample_does_not_double_count_prevalence():
    fcs = _family()
    fcs.add_sample("sha_a", [_c("AlphaMarker")])  # resumed extraction pass
    assert fcs.n_samples == 4
    pooled = {p.candidate.value: p for p in fcs.pool()}
    assert pooled["AlphaMarker"].n_containing == 1
    assert "SharedMarker" in pooled
    assert pooled["SharedMarker"].n_containing == 2  # sha_a's set was replaced


def test_support_excluding_is_the_other_samples_count():
    fcs = _family()
    key = _c("SharedMarker").key()
    assert fcs.support(key) == 3
    assert fcs.support_excluding(key, "sha_a") == 2
    assert fcs.support_excluding(key, "sha_d") == 3


def test_goodware_df_and_rate_from_df_index():
    fcs = _family()
    df = DFIndex(df={"kernel32.dll": 400}, n_docs=1000, source="G_stats")
    pooled = {p.candidate.value: p for p in fcs.pool(df_index=df)}
    assert pooled["kernel32.dll"].goodware_df == 400
    assert pooled["kernel32.dll"].goodware_rate == 0.4
    assert pooled["SharedMarker"].goodware_df == 0
    assert "kernel32.dll" in df and "SharedMarker" not in df


def test_pool_min_support_filter_and_deterministic_order():
    fcs = _family()
    pooled = fcs.pool(min_support=3)
    assert [p.candidate.value for p in pooled] == ["kernel32.dll", "SharedMarker"]


def test_attribution_scores_take_family_max():
    fcs = FamilyCandidateSet("f")
    fcs.add_sample("s1", [_c("HexyMarker", attribution_bin=0.2, attribution_fam=0.9)])
    fcs.add_sample("s2", [_c("HexyMarker", attribution_bin=0.7, attribution_fam=0.1)])
    p = fcs.pool()[0]
    assert p.attribution_bin == 0.7
    assert p.attribution_fam == 0.9


def test_xfam_index_counts_families_and_blocks_leakage():
    f1, f2 = _family("fam1"), _family("fam2")
    index, n = build_xfam_index(
        {"fam1": f1.keys(), "fam2": f2.keys()}, allowed_families=["fam1", "fam2"]
    )
    assert n == 2
    assert index[_c("kernel32.dll").key()] == 2
    assert index[_c("AlphaMarker").key()] == 2  # both fixtures share it
    with pytest.raises(ValueError, match="leak"):
        build_xfam_index({"F_test_family": f1.keys()}, allowed_families=["fam1"])


def test_pool_families_wires_promiscuity_through():
    f1, f2 = _family("fam1"), _family("fam2")
    out = pool_families([f1, f2], allowed_xfam_families=["fam1", "fam2"])
    p = {x.candidate.value: x for x in out["fam1"]}["kernel32.dll"]
    assert p.xfam_promiscuity == 2
    assert p.xfam_n_families == 2
    assert p.xfam_rate == 1.0


def test_pool_families_requires_explicit_leakage_intent():
    # A defaulted guard is an accidental off-switch; omitting it must fail loudly.
    f1 = _family("fam1")
    with pytest.raises(ValueError, match="allowed_xfam_families"):
        pool_families([f1])
    assert pool_families([f1], allow_all=True)["fam1"]


def test_positive_keys_uses_total_support_convention():
    # Convention: m is a TOTAL support count, sample included (see docstring).
    fcs = _family()
    df = DFIndex(df={"kernel32.dll": 400}, n_docs=1000)
    pos = fcs.positive_keys(m=3, df_index=df)
    # SharedMarker: total support 3 >= m, absent from goodware -> positive.
    assert _c("SharedMarker").key() in pos
    # kernel32.dll: support 4 but present in goodware -> negative.
    assert _c("kernel32.dll").key() not in pos
    # AlphaMarker: support 1 < m -> negative. Real negatives exist, so the
    # primary scorer is plain supervised, not PU (EXP2_DESIGN §6).
    assert _c("AlphaMarker").key() not in pos
    # Total-count, not "m others": at m=3 SharedMarker (support 3, i.e. 2 others
    # for any given holder) is positive. The strict others-count is a separate
    # call.
    assert fcs.support_excluding(_c("SharedMarker").key(), "sha_a") == 2
    assert _c("SharedMarker").key() not in fcs.positive_keys(m=4, df_index=df)


def test_default_m_matches_design_default():
    assert FamilyCandidateSet.default_m(10) == 2
    assert FamilyCandidateSet.default_m(50) == 10
    assert FamilyCandidateSet.default_m(1) == 2


def test_features_are_complete_and_finite():
    fcs = _family()
    df = DFIndex(df={"kernel32.dll": 400}, n_docs=1000)
    p = fcs.pool(df_index=df)[0]
    feats = p.features()
    expected = {
        "length", "printable_len", "entropy", "frac_alpha", "frac_digit",
        "has_space", "prevalence",
        "goodware_rate", "xfam_promiscuity", "xfam_rate",
        "attribution_bin", "attribution_fam",
    }
    assert set(feats) == expected
    assert all(isinstance(v, float) and v == v for v in feats.values())


def test_raw_support_counts_are_reported_but_never_featurized():
    """Ruling 2026-08-20: n_containing carries family size and goodware_df is
    not comparable across indexes, so both stay in to_dict and out of the
    scorer's view."""
    fcs = _family()
    p = fcs.pool(df_index=DFIndex(df={"kernel32.dll": 400}, n_docs=1000))[0]
    assert "n_containing" not in p.features()
    assert "goodware_df" not in p.features()
    assert "n_containing" in p.to_dict()
    assert "goodware_df" in p.to_dict()


def test_empty_family_pools_without_dividing_by_zero():
    fcs = FamilyCandidateSet("empty")
    assert fcs.pool() == []
    assert fcs.n_samples == 0


def test_value_entropy_bounds():
    assert value_entropy("") == 0.0
    assert value_entropy("aaaa") == 0.0
    assert value_entropy("ab") == pytest.approx(1.0)


def test_pooled_to_dict_is_json_ready():
    import json
    fcs = _family()
    d = fcs.pool()[0].to_dict()
    assert json.loads(json.dumps(d))["prevalence"] == 1.0


# ==========================================================================
# Stoplist
# ==========================================================================

def test_generic_and_packer_sections_are_stopped():
    sl = Stoplist()
    assert sl.hits(Candidate(value=".text", ctype=CType.PE_SECTION)) == "generic_section"
    assert sl.hits(Candidate(value=".RSRC", ctype=CType.PE_SECTION)) == "generic_section"
    assert sl.hits(Candidate(value="UPX0", ctype="SECTION_NAME")) == "packer_section"


def test_system_dlls_exact_and_patterned():
    sl = Stoplist()
    assert sl.hits(Candidate(value="KERNEL32.dll", ctype=CType.IMPORT)) == "system_dll"
    assert sl.hits(Candidate(value="msvcp140.dll", ctype=CType.IMPORT)) == \
        "system_dll_pattern"
    assert sl.hits(Candidate(value="api-ms-win-core-x-l1-1-0.dll",
                             ctype="PE_IMPORT_DLL")) == "system_dll_pattern"
    assert sl.hits(Candidate(value="universal_import_test.dll",
                             ctype=CType.IMPORT)) is None


def test_universal_imports_stopped_but_suspicious_apis_survive():
    sl = Stoplist()
    assert sl.hits(Candidate(value="GetProcAddress",
                             ctype=CType.IMPORT)) == "universal_import"
    # Genuinely suspicious APIs are left for the DF index and the scorer, which
    # can weigh them in context rather than dropping them outright.
    assert sl.hits(Candidate(value="CreateRemoteThread", ctype=CType.IMPORT)) is None
    assert sl.hits(Candidate(value="VirtualAllocEx", ctype=CType.IMPORT)) is None


def test_boilerplate_substrings_stopped_on_text_candidates():
    sl = Stoplist()
    v = "!This program cannot be run in DOS mode."
    assert sl.hits(Candidate(value=v, ctype=CType.STRING_ASCII)).startswith(
        "boilerplate")
    assert sl.hits(Candidate(value="<?xml version=\"1.0\"?>",
                             ctype=CType.STRING_ASCII)).startswith("boilerplate")
    assert sl.hits(Candidate(value="EvilFamilyMarker42",
                             ctype=CType.STRING_ASCII)) is None


def test_stoplist_is_type_aware():
    sl = Stoplist()
    # ".text" as a *string* is not the generic-section problem; only the section
    # candidate is stopped.
    assert sl.hits(Candidate(value=".text", ctype=CType.PE_SECTION)) is not None
    assert sl.hits(Candidate(value=".textmarker", ctype=CType.STRING_ASCII)) is None
    # A hash is never a stoplist concern.
    assert sl.hits(Candidate(value=SHA256, ctype=CType.HASH_SHA256)) is None


def test_runtime_language_markers_stopped_but_family_signal_survives():
    # The goodware corpus is VB6/.NET-poor, so the DF index cannot see these as
    # generic; the curated stoplist is the backstop (NOTE.md R17). VB6 __vba*
    # thunks and .NET entry stubs must die, or a VB6 family marker matches every
    # VB6 program on earth (the pre-wipe FP catastrophe).
    sl = Stoplist()
    for name in ("__vbaStrMove", "__vbaFreeStrList", "__vbaHresultCheckObj"):
        assert sl.hits(Candidate(value=name, ctype=CType.IMPORT)) == \
            "runtime_import_pattern", name
    assert sl.hits(Candidate(value="_CorExeMain", ctype=CType.IMPORT)) == \
        "runtime_import"
    assert sl.hits(Candidate(value="MSVBVM60.DLL", ctype=CType.IMPORT)) == \
        "runtime_import"
    assert sl.hits(Candidate(value="System.Reflection.Assembly",
                             ctype=CType.STRING_ASCII)).startswith("dotnet_runtime")
    # Family signal that merely lives in a VB6/.NET binary must NOT be stopped:
    # networking, injection APIs, and family-named strings all survive.
    for keep, ct in (("System.Net.Sockets.Socket", CType.STRING_ASCII),
                     ("CreateRemoteThread", CType.IMPORT),
                     ("VirtualAllocEx", CType.IMPORT),
                     ("MyCustomToStringHelper", CType.STRING_ASCII)):
        assert sl.hits(Candidate(value=keep, ctype=ct)) is None, keep


def test_dll_named_string_candidates_are_stopped():
    sl = Stoplist()
    assert sl.hits(Candidate(value="ntdll.dll", ctype=CType.STRING_ASCII)) == \
        "system_dll"
    off = Stoplist(dll_names_as_strings=False)
    assert off.hits(Candidate(value="ntdll.dll", ctype=CType.STRING_ASCII)) is None


def test_stoplist_filter_returns_kept_and_reasons():
    sl = Stoplist()
    cands = [
        Candidate(value="EvilFamilyMarker42", ctype=CType.STRING_ASCII),
        Candidate(value=".data", ctype=CType.PE_SECTION),
        Candidate(value="user32.dll", ctype=CType.IMPORT),
    ]
    kept, dropped = sl.filter(cands)
    assert [c.value for c in kept] == ["EvilFamilyMarker42"]
    assert set(dropped) == {"generic_section", "system_dll"}


def test_stoplist_extras():
    sl = Stoplist.with_extras(exact=["EvilFamilyMarker42"], substrings=["CustomJunk"])
    assert sl.hits(Candidate(value="EvilFamilyMarker42",
                             ctype=CType.STRING_ASCII)) == "extra_exact"
    assert sl.hits(Candidate(value="prefix customjunk suffix",
                             ctype=CType.STRING_ASCII)).startswith("extra_substring")


# ==========================================================================
# Byte-faithfulness of rendering (the failure mode that silently kills rules)
# ==========================================================================

@pytest.mark.parametrize("raw", [
    "EvilStager\u2019s loader",   # typographic apostrophe from a PDF
    'Say "hi"\\path',             # quote and backslash together
    "tab\there",
    "C:\\Users\\Public\\Evil.EXE",
    "line\nbreak",
    "nul\x00byte",
])
def test_rendered_string_still_matches_the_original_bytes(raw):
    # If escaping is wrong the rule still compiles but never fires, so a parse
    # check is not enough -- scan the original bytes back.
    yara = pytest.importorskip("yara")
    c = Candidate(value=raw, ctype=CType.STRING_ASCII)
    line = render_string(c, "$s")
    rules = yara.compile(source="rule T {strings: " + line + " condition: $s}")
    assert rules.match(data=b"AAAA" + raw.encode("utf-8") + b"BBBB")


def test_rendered_hex_string_matches_the_original_bytes():
    yara = pytest.importorskip("yara")
    c = Candidate(value="55 8B EC 83 EC ?? 53 56", ctype=CType.HEX_SPAN)
    line = render_string(c, "$h")
    rules = yara.compile(source="rule T {strings: " + line + " condition: $h}")
    payload = bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40, 0x53, 0x56])
    assert rules.match(data=b"\x90" * 8 + payload + b"\x90" * 8)


def test_nocase_rendering_matches_case_variants():
    yara = pytest.importorskip("yara")
    c = Candidate(value="Evil.Example.COM", ctype=CType.DOMAIN)
    line = render_string(c, "$d")
    rules = yara.compile(source="rule T {strings: " + line + " condition: $d}")
    assert rules.match(data=b"visit evil.example.com now")


# ==========================================================================
# Import-order guard (HANDOFF lesson)
# ==========================================================================

def test_isb_core_does_not_import_yaramod_or_tensorflow():
    # This package is imported from everywhere; if it dragged in yaramod (or
    # anything pulling TensorFlow via HF evaluate) it would dictate import order
    # for every caller.
    import subprocess

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (
        "import sys; sys.path.insert(0, %r); import YaraGen.ISB; "
        "bad=[m for m in ('yaramod','tensorflow','evaluate','torch') "
        "if m in sys.modules]; print(','.join(bad))" % root
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ""

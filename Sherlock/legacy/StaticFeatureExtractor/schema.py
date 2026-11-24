"""
Typed schema for static feature extraction output.

All features map back to the 21-type IOC schema used by the NER pipeline:
    MD5, SHA-1, SHA-256, SSDEEP, FILE, REGISTRY, MAGIC, MAGIKA, IP,
    PE.TYPELIB, PE.RESOURCES, PE.SECTION, PE.SECTION.MD5, PE.SECTION.NAME,
    PE.SECTION.SIZE, PE.SECTION.ENTROPY,
    DOTNET.NAME, DOTNET.REVISION_NUMBER, DOTNET.ASSEMBLY_NAME,
    DOTNET.VERSION, DOTNET.STREAM
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Any
import json


class FileFormat(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    DOTNET = "dotnet"          # PE-CLR, treated specially
    SCRIPT = "script"          # JS, VBS, PS1, PY, sh, BAT
    OFFICE = "office"          # doc, docx, xls, xlsx, ppt, pptx
    PDF = "pdf"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────────────────────────────
#  Hash and file-typing features (apply to every format)
# ──────────────────────────────────────────────────────────────────────

@dataclass
class HashFeatures:
    md5: str
    sha1: str
    sha256: str
    ssdeep: str
    imphash: Optional[str] = None         # PE only
    rich_pv_hash: Optional[str] = None    # PE only — Rich header
    authentihash: Optional[str] = None    # PE only — Authenticode hash
    telfhash: Optional[str] = None        # ELF symbol-table hash
    machoc_hash: Optional[str] = None     # Mach-O fuzzy hash


@dataclass
class FileTypeFeatures:
    libmagic: str
    magika: str
    magika_score: float
    file_size: int
    detected_format: FileFormat


# ──────────────────────────────────────────────────────────────────────
#  Common section feature (PE/ELF/Mach-O share this shape)
# ──────────────────────────────────────────────────────────────────────

@dataclass
class SectionFeature:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    md5: str
    characteristics: list[str] = field(default_factory=list)
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True
    suspicious: bool = False              # heuristic: high entropy + W^X violation, etc.


# ──────────────────────────────────────────────────────────────────────
#  PE-specific features
# ──────────────────────────────────────────────────────────────────────

@dataclass
class PEHeaderFeatures:
    machine: str
    timestamp: int
    timestamp_iso: str
    subsystem: str
    dll_characteristics: list[str]
    image_base: int
    entry_point: int
    n_sections: int
    is_dotnet: bool = False
    is_signed: bool = False
    has_tls: bool = False
    has_debug: bool = False
    has_resources: bool = False
    has_relocations: bool = False
    rich_header_entries: list[dict] = field(default_factory=list)


@dataclass
class ImportFeatures:
    dlls: list[str]
    functions: list[tuple[str, str]]      # (dll, function_name)
    imphash: str
    n_imports: int
    suspicious_apis: list[str] = field(default_factory=list)


@dataclass
class ExportFeatures:
    dll_name: Optional[str]
    functions: list[str]
    n_exports: int


@dataclass
class ResourceFeature:
    type: str
    name: str
    language: int
    size: int
    entropy: float
    sha256: str


# ──────────────────────────────────────────────────────────────────────
#  .NET / CLR features
# ──────────────────────────────────────────────────────────────────────

@dataclass
class DotNetFeatures:
    assembly_name: Optional[str] = None
    module_name: Optional[str] = None
    version: Optional[str] = None
    revision_number: Optional[int] = None
    streams: list[str] = field(default_factory=list)
    typelib_id: Optional[str] = None
    guids: list[str] = field(default_factory=list)
    n_types: int = 0
    n_methods: int = 0
    n_strings: int = 0


# ──────────────────────────────────────────────────────────────────────
#  ELF features
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ELFHeaderFeatures:
    machine: str
    file_type: str                         # EXEC, DYN, REL, ...
    entry_point: int
    n_sections: int
    n_segments: int
    interpreter: Optional[str] = None
    is_stripped: bool = False
    has_dynamic: bool = False


@dataclass
class ELFSymbolFeatures:
    imported_libraries: list[str]
    imported_functions: list[str]
    exported_functions: list[str]
    n_symbols: int
    telfhash: str


# ──────────────────────────────────────────────────────────────────────
#  Mach-O features
# ──────────────────────────────────────────────────────────────────────

@dataclass
class MachOHeaderFeatures:
    cpu_type: str
    cpu_subtype: str
    file_type: str                         # EXECUTE, DYLIB, BUNDLE, ...
    n_commands: int
    flags: list[str] = field(default_factory=list)
    is_fat: bool = False
    is_signed: bool = False


# ──────────────────────────────────────────────────────────────────────
#  Script / Office / PDF features
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ScriptFeatures:
    language: str                          # ps1, vbs, js, py, bash, ...
    line_count: int
    char_count: int
    avg_line_length: float
    entropy: float
    obfuscation_score: float               # 0–1; high = likely obfuscated
    suspicious_keywords: list[str] = field(default_factory=list)
    base64_blobs: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    powershell_flags: list[str] = field(default_factory=list)


@dataclass
class OfficeFeatures:
    file_format: str                       # ole, ooxml, rtf
    has_macros: bool
    macro_languages: list[str] = field(default_factory=list)
    macro_code: list[str] = field(default_factory=list)   # extracted source
    has_external_refs: bool = False
    has_dde: bool = False
    suspicious_keywords: list[str] = field(default_factory=list)
    embedded_objects: list[str] = field(default_factory=list)
    autoexec_triggers: list[str] = field(default_factory=list)


@dataclass
class PDFFeatures:
    n_pages: int
    has_javascript: bool
    has_embedded_files: bool
    has_openaction: bool
    has_launch: bool
    has_forms: bool
    suspicious_keywords: list[str] = field(default_factory=list)
    embedded_files: list[str] = field(default_factory=list)
    javascript_blobs: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
#  String / byte features (universal across formats)
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StringFeatures:
    n_strings: int
    n_urls: int
    n_paths: int
    n_registry_keys: int
    n_ips: int
    avg_length: float
    entropy: float
    printable_ratio: float
    paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    floss_used: bool = False                # True if FLOSS was opted in


@dataclass
class ByteHistogramFeatures:
    """EMBER-style raw byte features for ML detector."""
    histogram: list[int]                    # 256-d
    entropy: float
    byte_entropy_histogram: list[float]     # 16×16 = 256-d flattened


# ──────────────────────────────────────────────────────────────────────
#  Top-level container
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StaticFeatures:
    path: str
    hashes: HashFeatures
    file_type: FileTypeFeatures
    byte_stats: Optional[ByteHistogramFeatures] = None
    strings: Optional[StringFeatures] = None

    # PE / .NET
    pe_header: Optional[PEHeaderFeatures] = None
    pe_sections: list[SectionFeature] = field(default_factory=list)
    pe_imports: Optional[ImportFeatures] = None
    pe_exports: Optional[ExportFeatures] = None
    pe_resources: list[ResourceFeature] = field(default_factory=list)
    dotnet: Optional[DotNetFeatures] = None

    # ELF
    elf_header: Optional[ELFHeaderFeatures] = None
    elf_sections: list[SectionFeature] = field(default_factory=list)
    elf_symbols: Optional[ELFSymbolFeatures] = None

    # Mach-O
    macho_header: Optional[MachOHeaderFeatures] = None
    macho_sections: list[SectionFeature] = field(default_factory=list)

    # Scripts / Office / PDF
    script: Optional[ScriptFeatures] = None
    office: Optional[OfficeFeatures] = None
    pdf: Optional[PDFFeatures] = None

    parse_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.to_dict(), default=str, **kwargs)

    # ──────────────────────────────────────────────────────────────────
    #  IOC schema mapping  (21-type flat schema)
    # ──────────────────────────────────────────────────────────────────
    def to_iocs(self) -> list[dict[str, Any]]:
        """
        Flatten to the 21-type IOC schema. Each IOC: {type, value, context}.
        Used to compare structured-extractor output against the NER pipeline.
        """
        iocs: list[dict[str, Any]] = []
        h = self.hashes
        iocs.append({"type": "MD5", "value": h.md5, "context": {}})
        iocs.append({"type": "SHA-1", "value": h.sha1, "context": {}})
        iocs.append({"type": "SHA-256", "value": h.sha256, "context": {}})
        iocs.append({"type": "SSDEEP", "value": h.ssdeep, "context": {}})

        iocs.append({"type": "MAGIC", "value": self.file_type.libmagic, "context": {}})
        iocs.append({"type": "MAGIKA", "value": self.file_type.magika, "context": {}})

        # PE sections → four IOCs each
        for sec in self.pe_sections:
            ctx = {"section": sec.name}
            iocs.append({"type": "PE.SECTION", "value": sec.name, "context": ctx})
            iocs.append({"type": "PE.SECTION.NAME", "value": sec.name, "context": ctx})
            iocs.append({"type": "PE.SECTION.SIZE", "value": sec.raw_size, "context": ctx})
            iocs.append({"type": "PE.SECTION.ENTROPY", "value": sec.entropy, "context": ctx})
            iocs.append({"type": "PE.SECTION.MD5", "value": sec.md5, "context": ctx})

        # PE resources
        for res in self.pe_resources:
            iocs.append({
                "type": "PE.RESOURCES",
                "value": f"{res.type}/{res.name}",
                "context": {"sha256": res.sha256, "size": res.size},
            })

        # .NET features
        if self.dotnet:
            d = self.dotnet
            if d.assembly_name:
                iocs.append({"type": "DOTNET.ASSEMBLY_NAME", "value": d.assembly_name, "context": {}})
            if d.module_name:
                iocs.append({"type": "DOTNET.NAME", "value": d.module_name, "context": {}})
            if d.version:
                iocs.append({"type": "DOTNET.VERSION", "value": d.version, "context": {}})
            if d.revision_number is not None:
                iocs.append({"type": "DOTNET.REVISION_NUMBER", "value": d.revision_number, "context": {}})
            for stream in d.streams:
                iocs.append({"type": "DOTNET.STREAM", "value": stream, "context": {}})
            if d.typelib_id:
                iocs.append({"type": "PE.TYPELIB", "value": d.typelib_id, "context": {}})

        # String-derived FILE / REGISTRY / IP candidates
        if self.strings:
            for p in self.strings.paths:
                iocs.append({"type": "FILE", "value": p, "context": {"source": "strings"}})
            for r in self.strings.registry_keys:
                iocs.append({"type": "REGISTRY", "value": r, "context": {"source": "strings"}})
            for ip in self.strings.ips:
                iocs.append({"type": "IP", "value": ip, "context": {"source": "strings"}})

        return iocs

    # ──────────────────────────────────────────────────────────────────
    #  YARA condition emitter
    # ──────────────────────────────────────────────────────────────────
    def to_yara_conditions(self) -> list[str]:
        """
        Emit YARA condition fragments. Composes with AutoPYara's hex-byte
        strings to form a complete rule.

        These are the *high-confidence* conditions only — entropy thresholds,
        imphash, and structural invariants. String IOCs (URLs, paths) are
        deliberately excluded here; AutoPYara handles those better via
        clustering.

        SHA-256 is intentionally NOT emitted as a condition: it identifies
        exactly one file and won't survive any recompilation. The hash
        belongs in the meta block as a fingerprint, not as a hunting
        condition. The pipeline orchestrator handles that placement.
        """
        conds: list[str] = []
        h = self.hashes

        if h.imphash:
            conds.append(f'pe.imphash() == "{h.imphash}"')

        if self.pe_header:
            ph = self.pe_header
            conds.append(f"pe.number_of_sections == {ph.n_sections}")
            if ph.timestamp:
                conds.append(f"pe.timestamp == {ph.timestamp}")

        # Suspicious section entropy as a behavioral signal
        for i, sec in enumerate(self.pe_sections):
            if sec.suspicious and sec.entropy > 7.0:
                conds.append(
                    f"math.entropy(pe.sections[{i}].raw_data_offset, "
                    f"pe.sections[{i}].raw_data_size) > 7.0"
                )

        if self.dotnet and self.dotnet.typelib_id:
            conds.append(f'dotnet.typelib == "{self.dotnet.typelib_id}"')

        return conds

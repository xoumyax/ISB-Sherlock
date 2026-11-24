"""
StaticIOCExtractor — the top-level orchestrator.

Routes to the right format-specific extractor based on Magika + libmagic
detection. Always produces a StaticFeatures object, even on parse failure.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional, Union

from .schema import StaticFeatures, FileFormat
from .common import (
    compute_hashes,
    compute_byte_features,
    detect_file_type,
    compute_string_features,
)
from . import pe as pe_ext
from . import elf as elf_ext
from . import macho as macho_ext
from . import script as script_ext
from . import office as office_ext
from . import pdf as pdf_ext

logger = logging.getLogger(__name__)


class StaticIOCExtractor:
    """
    SOTA static feature extractor for malware IOC extraction.

    Usage:
        extractor = StaticIOCExtractor("/path/to/sample.bin")
        features = extractor.extract()
        iocs = features.to_iocs()
        yara_conds = features.to_yara_conditions()

    The extractor never raises on a malformed sample — parse failures
    are recorded in features.parse_errors and the extraction continues
    with whatever subset of features was recoverable.

    Args:
        path: Path to the sample file.
        use_floss: If True, run FLOSS for deobfuscated/stack strings.
                   Slow (5–60s per binary) but recovers strings that
                   static extraction misses entirely.
        compute_byte_stats: If True, compute EMBER-style byte histograms
                            (needed for the ML detector, optional otherwise).
        max_resources: Cap on the number of PE resources to retain in the
                       output (avoid memory blow-up on resource-stuffed
                       installers). Default 256.
    """

    def __init__(
        self,
        path: Union[str, Path],
        *,
        use_floss: bool = False,
        compute_byte_stats: bool = True,
        max_resources: int = 256,
    ):
        self.path = Path(path)
        self.use_floss = use_floss
        self.compute_byte_stats = compute_byte_stats
        self.max_resources = max_resources
        self._data: Optional[bytes] = None

    @property
    def data(self) -> bytes:
        if self._data is None:
            self._data = self.path.read_bytes()
        return self._data

    # ──────────────────────────────────────────────────────────────────
    #  Main entry point
    # ──────────────────────────────────────────────────────────────────

    def extract(self) -> StaticFeatures:
        if not self.path.exists():
            raise FileNotFoundError(f"Sample not found: {self.path}")
        if not self.path.is_file():
            raise ValueError(f"Not a file: {self.path}")

        data = self.data
        errors: list[str] = []

        # 1. Universal: hashes + file typing
        hashes = compute_hashes(data)
        file_type = detect_file_type(self.path, data)

        features = StaticFeatures(
            path=str(self.path),
            hashes=hashes,
            file_type=file_type,
            parse_errors=errors,
        )

        # 2. EMBER-style byte stats (universal, needed for ML detector)
        if self.compute_byte_stats:
            try:
                features.byte_stats = compute_byte_features(data)
            except Exception as exc:
                errors.append(f"byte_stats: {exc!r}")

        # 3. Universal: string extraction (with optional FLOSS)
        try:
            features.strings = compute_string_features(data, use_floss=self.use_floss)
        except Exception as exc:
            errors.append(f"strings: {exc!r}")

        # 4. Format-specific dispatch
        fmt = file_type.detected_format
        try:
            if fmt == FileFormat.PE:
                self._extract_pe(features, data)
            elif fmt == FileFormat.ELF:
                self._extract_elf(features, data)
            elif fmt == FileFormat.MACHO:
                self._extract_macho(features, data)
            elif fmt == FileFormat.SCRIPT:
                self._extract_script(features, data, file_type.magika)
            elif fmt == FileFormat.OFFICE:
                self._extract_office(features, data)
            elif fmt == FileFormat.PDF:
                self._extract_pdf(features, data)
            else:
                logger.info("Unknown format for %s; only universal features extracted",
                             self.path)
        except Exception as exc:
            errors.append(f"{fmt}: {exc!r}")
            logger.exception("Format-specific extraction failed for %s", self.path)

        return features

    # ──────────────────────────────────────────────────────────────────
    #  Format dispatch helpers
    # ──────────────────────────────────────────────────────────────────

    def _extract_pe(self, f: StaticFeatures, data: bytes) -> None:
        # Format-specific hashes
        f.hashes.imphash = pe_ext.compute_imphash(data)
        f.hashes.authentihash = pe_ext.compute_authentihash(data)
        f.hashes.rich_pv_hash = pe_ext.compute_rich_pv_hash(data)

        binary = pe_ext.parse_pe(data)
        if binary is None:
            f.pe_header, f.pe_sections = pe_ext.extract_pe_fallback(data)
            if f.pe_header or f.pe_sections:
                f.parse_errors.append("pe: LIEF parse failed; used lightweight PE fallback")
            else:
                f.parse_errors.append("pe: LIEF parse failed")
            return

        f.pe_header = pe_ext.extract_pe_header(binary)
        f.pe_sections = pe_ext.extract_pe_sections(binary)
        f.pe_imports = pe_ext.extract_pe_imports(binary, f.hashes.imphash or "")
        f.pe_exports = pe_ext.extract_pe_exports(binary)

        resources = pe_ext.extract_pe_resources(binary)
        if len(resources) > self.max_resources:
            logger.info("Truncating PE resources from %d to %d",
                         len(resources), self.max_resources)
            f.parse_errors.append(
                f"pe.resources: truncated {len(resources)} → {self.max_resources}"
            )
            resources = resources[:self.max_resources]
        f.pe_resources = resources

        f.dotnet = pe_ext.extract_dotnet(data, binary)

    def _extract_elf(self, f: StaticFeatures, data: bytes) -> None:
        binary = elf_ext.parse_elf(data)
        if binary is None:
            f.parse_errors.append("elf: LIEF parse failed")
            return
        f.elf_header = elf_ext.extract_elf_header(binary)
        f.elf_sections = elf_ext.extract_elf_sections(binary)
        f.elf_symbols = elf_ext.extract_elf_symbols(binary)
        if f.elf_symbols and f.elf_symbols.telfhash:
            f.hashes.telfhash = f.elf_symbols.telfhash

    def _extract_macho(self, f: StaticFeatures, data: bytes) -> None:
        fat = macho_ext.parse_macho(data)
        if fat is None:
            f.parse_errors.append("macho: LIEF parse failed")
            return
        f.macho_header = macho_ext.extract_macho_header(fat)
        f.macho_sections = macho_ext.extract_macho_sections(fat)

    def _extract_script(self, f: StaticFeatures, data: bytes, hint: str) -> None:
        f.script = script_ext.extract_script(data, magika_hint=hint)

    def _extract_office(self, f: StaticFeatures, data: bytes) -> None:
        f.office = office_ext.extract_office(data)

    def _extract_pdf(self, f: StaticFeatures, data: bytes) -> None:
        f.pdf = pdf_ext.extract_pdf(data)


# ──────────────────────────────────────────────────────────────────────
#  Convenience function
# ──────────────────────────────────────────────────────────────────────

def extract(path: Union[str, Path], **kwargs) -> StaticFeatures:
    """One-shot extraction. Equivalent to StaticIOCExtractor(path, **kw).extract()."""
    return StaticIOCExtractor(path, **kwargs).extract()

"""ELF feature extractor (Linux binaries)."""
from __future__ import annotations
import hashlib
import logging
from typing import Optional

from .schema import ELFHeaderFeatures, ELFSymbolFeatures, SectionFeature
from .common import shannon_entropy

logger = logging.getLogger(__name__)


def parse_elf(data: bytes):
    try:
        import lief
        try:
            lief.logging.disable()
        except Exception:
            pass
        return lief.ELF.parse(list(data))
    except ImportError as exc:
        logger.info("LIEF ELF parser unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.warning("LIEF ELF parse failed: %s", exc)
        return None


def extract_elf_header(binary) -> Optional[ELFHeaderFeatures]:
    try:
        h = binary.header
        interp = None
        try:
            interp = binary.interpreter or None
        except Exception:
            pass

        return ELFHeaderFeatures(
            machine=str(h.machine_type).split(".")[-1],
            file_type=str(h.file_type).split(".")[-1],
            entry_point=int(h.entrypoint),
            n_sections=len(binary.sections),
            n_segments=len(binary.segments),
            interpreter=interp,
            is_stripped=not bool(binary.symbols),
            has_dynamic=bool(binary.dynamic_entries),
        )
    except Exception as exc:
        logger.warning("ELF header extraction failed: %s", exc)
        return None


def extract_elf_sections(binary) -> list[SectionFeature]:
    out: list[SectionFeature] = []
    for sec in binary.sections:
        try:
            content = bytes(sec.content)
            ent = shannon_entropy(content)
            md5 = hashlib.md5(content).hexdigest() if content else ""
            flags = []
            try:
                for f in sec.flags_list:
                    flags.append(str(f).split(".")[-1])
            except Exception:
                pass

            out.append(SectionFeature(
                name=sec.name or "<unnamed>",
                virtual_size=int(sec.virtual_address) if hasattr(sec, "virtual_address") else 0,
                raw_size=int(sec.size),
                entropy=ent,
                md5=md5,
                characteristics=flags,
                is_executable="EXECINSTR" in flags,
                is_writable="WRITE" in flags,
                is_readable="ALLOC" in flags,
                suspicious=ent > 7.0 and "EXECINSTR" in flags and "WRITE" in flags,
            ))
        except Exception as exc:
            logger.warning("ELF section extraction failed: %s", exc)
    return out


def extract_elf_symbols(binary) -> Optional[ELFSymbolFeatures]:
    try:
        libs = list(binary.libraries) if hasattr(binary, "libraries") else []
        imp_funcs: list[str] = []
        exp_funcs: list[str] = []

        try:
            for sym in binary.imported_symbols:
                if sym.name:
                    imp_funcs.append(sym.name)
        except Exception:
            pass

        try:
            for sym in binary.exported_symbols:
                if sym.name:
                    exp_funcs.append(sym.name)
        except Exception:
            pass

        n_total = 0
        try:
            n_total = len(list(binary.symbols))
        except Exception:
            pass

        # telfhash via lief if available, else compute a simple proxy
        telfhash = ""
        try:
            telfhash = binary.telfhash() if hasattr(binary, "telfhash") else ""
        except Exception:
            telfhash = ""

        return ELFSymbolFeatures(
            imported_libraries=sorted(set(libs)),
            imported_functions=sorted(set(imp_funcs)),
            exported_functions=sorted(set(exp_funcs)),
            n_symbols=n_total,
            telfhash=telfhash or "",
        )
    except Exception as exc:
        logger.warning("ELF symbol extraction failed: %s", exc)
        return None

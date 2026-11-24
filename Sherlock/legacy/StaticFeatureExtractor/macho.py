"""Mach-O feature extractor (macOS / iOS binaries)."""
from __future__ import annotations
import hashlib
import logging
from typing import Optional

from .schema import MachOHeaderFeatures, SectionFeature
from .common import shannon_entropy

logger = logging.getLogger(__name__)


def parse_macho(data: bytes):
    try:
        import lief
        try:
            lief.logging.disable()
        except Exception:
            pass
        return lief.MachO.parse(list(data))
    except ImportError as exc:
        logger.info("LIEF Mach-O parser unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.warning("LIEF Mach-O parse failed: %s", exc)
        return None


def _first_binary(fat_or_binary):
    """Mach-O parse returns a FatBinary; pick the first slice."""
    try:
        if hasattr(fat_or_binary, "size") and fat_or_binary.size > 0:
            return fat_or_binary.at(0)
    except Exception:
        pass
    return fat_or_binary


def extract_macho_header(fat) -> Optional[MachOHeaderFeatures]:
    try:
        binary = _first_binary(fat)
        h = binary.header
        flags = []
        try:
            for f in h.flags_list:
                flags.append(str(f).split(".")[-1])
        except Exception:
            pass

        is_signed = False
        try:
            is_signed = binary.has_code_signature
        except Exception:
            pass

        is_fat = False
        try:
            is_fat = hasattr(fat, "size") and fat.size > 1
        except Exception:
            pass

        return MachOHeaderFeatures(
            cpu_type=str(h.cpu_type).split(".")[-1],
            cpu_subtype=str(getattr(h, "cpu_subtype", "?")),
            file_type=str(h.file_type).split(".")[-1],
            n_commands=int(h.nb_cmds),
            flags=flags,
            is_fat=is_fat,
            is_signed=bool(is_signed),
        )
    except Exception as exc:
        logger.warning("Mach-O header extraction failed: %s", exc)
        return None


def extract_macho_sections(fat) -> list[SectionFeature]:
    out: list[SectionFeature] = []
    try:
        binary = _first_binary(fat)
        for sec in binary.sections:
            try:
                content = bytes(sec.content)
                ent = shannon_entropy(content)
                md5 = hashlib.md5(content).hexdigest() if content else ""

                flags: list[str] = []
                try:
                    for f in sec.flags_list:
                        flags.append(str(f).split(".")[-1])
                except Exception:
                    pass

                seg_name = ""
                try:
                    seg_name = sec.segment.name if sec.segment else ""
                except Exception:
                    pass

                full_name = f"{seg_name},{sec.name}" if seg_name else sec.name

                # Mach-O W^X heuristic: __TEXT segment should not be writable
                is_x = "PURE_INSTRUCTIONS" in flags or seg_name == "__TEXT"
                # Writable inferred from segment, not section
                is_w = False
                try:
                    if sec.segment:
                        is_w = bool(sec.segment.init_protection & 0x2)
                except Exception:
                    pass

                out.append(SectionFeature(
                    name=full_name or "<unnamed>",
                    virtual_size=int(sec.size),
                    raw_size=int(sec.size),
                    entropy=ent,
                    md5=md5,
                    characteristics=flags,
                    is_executable=is_x,
                    is_writable=is_w,
                    is_readable=True,
                    suspicious=ent > 7.0 and is_x and is_w,
                ))
            except Exception as exc:
                logger.warning("Mach-O section extraction failed: %s", exc)
    except Exception as exc:
        logger.warning("Mach-O section walk failed: %s", exc)
    return out

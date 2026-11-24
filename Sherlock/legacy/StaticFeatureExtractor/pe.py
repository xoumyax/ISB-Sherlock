"""
PE / .NET feature extractor.

Uses LIEF as the primary parser (more robust to malformed PEs than pefile),
falls back to pefile for imphash and Rich header (LIEF coverage is
inconsistent across versions). All operations are wrapped — the extractor
must never raise on a malformed sample.
"""
from __future__ import annotations
import datetime as _dt
import hashlib
import logging
import struct
from typing import Optional

from .schema import (
    PEHeaderFeatures,
    SectionFeature,
    ImportFeatures,
    ExportFeatures,
    ResourceFeature,
    DotNetFeatures,
)
from .common import shannon_entropy

logger = logging.getLogger(__name__)


# Curated list of APIs commonly abused by malware. This is the
# behavioral-static bridge for YARA condition synthesis.
SUSPICIOUS_APIS: frozenset[str] = frozenset({
    # Process / thread injection
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
    "SetThreadContext", "ResumeThread", "SuspendThread",
    # Memory manipulation
    "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "NtWriteVirtualMemory",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    # Process discovery / manipulation
    "OpenProcess", "NtOpenProcess", "Process32First", "Process32Next",
    "CreateToolhelp32Snapshot",
    # Hooking / persistence
    "SetWindowsHookEx", "SetWinEventHook",
    "RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx",
    # Network
    "InternetOpen", "InternetOpenUrl", "InternetReadFile", "HttpOpenRequest",
    "WinHttpOpen", "WinHttpConnect", "URLDownloadToFile",
    "WSAStartup", "socket", "connect", "send", "recv",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
    # Crypto
    "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
    "CryptGenKey", "CryptHashData",
    # Service / privilege
    "AdjustTokenPrivileges", "OpenServiceA", "CreateServiceA",
    "StartServiceA", "ChangeServiceConfig",
    # Shell / execution
    "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcess",
    "CreateProcessAsUser", "CreateProcessWithToken",
    # File / DLL loading
    "LoadLibrary", "LoadLibraryEx", "GetProcAddress",
    "LdrLoadDll", "LdrGetProcedureAddress",
})


def _section_characteristics(section) -> list[str]:
    """Return human-readable PE section characteristic flags from LIEF."""
    flags: list[str] = []
    chars = getattr(section, "characteristics_lists", None)
    if chars:
        for c in chars:
            flags.append(str(c).split(".")[-1])
    return flags


def _is_suspicious_section(section, entropy: float, characteristics: list[str]) -> bool:
    """Heuristic: high entropy + W^X violation, or non-standard name."""
    name = section.name.strip().lower()
    standard = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata",
                 ".idata", ".edata", ".tls", ".bss", ".debug"}

    has_w_and_x = (
        "MEM_WRITE" in characteristics and "MEM_EXECUTE" in characteristics
    )
    high_entropy = entropy > 7.0
    nonstandard_name = name not in standard and not name.startswith(".text")

    return high_entropy and (has_w_and_x or nonstandard_name)


def extract_pe_header(binary) -> Optional[PEHeaderFeatures]:
    """Extract PE optional/coff header features. Returns None on failure."""
    try:
        opt = binary.optional_header
        coff = binary.header

        ts = coff.time_date_stamps
        ts_iso = ""
        try:
            ts_iso = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            ts_iso = "invalid"

        dll_chars: list[str] = []
        try:
            for c in opt.dll_characteristics_lists:
                dll_chars.append(str(c).split(".")[-1])
        except Exception:
            pass

        rich_entries: list[dict] = []
        try:
            if binary.has_rich_header:
                rh = binary.rich_header
                for e in rh.entries:
                    rich_entries.append({
                        "id": int(e.id), "build_id": int(e.build_id),
                        "count": int(e.count),
                    })
        except Exception:
            pass

        return PEHeaderFeatures(
            machine=str(coff.machine).split(".")[-1],
            timestamp=ts,
            timestamp_iso=ts_iso,
            subsystem=str(opt.subsystem).split(".")[-1],
            dll_characteristics=dll_chars,
            image_base=int(opt.imagebase),
            entry_point=int(opt.addressof_entrypoint),
            n_sections=len(binary.sections),
            is_dotnet=bool(
                getattr(binary, "has_clr", False) or
                getattr(binary, "has_dot_net", False) or
                _has_clr_directory(binary)
            ),
            is_signed=bool(binary.has_signatures) if hasattr(binary, "has_signatures") else False,
            has_tls=bool(binary.has_tls),
            has_debug=bool(binary.has_debug),
            has_resources=bool(binary.has_resources),
            has_relocations=bool(binary.has_relocations),
            rich_header_entries=rich_entries,
        )
    except Exception as exc:
        logger.warning("PE header extraction failed: %s", exc)
        return None


def _has_clr_directory(binary) -> bool:
    """Detect .NET via the CLR data directory (index 14)."""
    try:
        for d in binary.data_directories:
            type_str = str(d.type).split(".")[-1].upper()
            if type_str in ("CLR_RUNTIME_HEADER", "CLR"):
                return d.size > 0 and d.rva > 0
    except Exception:
        pass
    return False


def extract_pe_sections(binary) -> list[SectionFeature]:
    """Extract per-section features."""
    out: list[SectionFeature] = []
    for sec in binary.sections:
        try:
            content = bytes(sec.content)
            ent = shannon_entropy(content)
            md5 = hashlib.md5(content).hexdigest() if content else ""
            chars = _section_characteristics(sec)

            out.append(SectionFeature(
                name=sec.name.strip("\x00").strip() or "<unnamed>",
                virtual_size=int(sec.virtual_size),
                raw_size=int(sec.sizeof_raw_data),
                entropy=ent,
                md5=md5,
                characteristics=chars,
                is_executable="MEM_EXECUTE" in chars,
                is_writable="MEM_WRITE" in chars,
                is_readable="MEM_READ" in chars,
                suspicious=_is_suspicious_section(sec, ent, chars),
            ))
        except Exception as exc:
            logger.warning("PE section %s extraction failed: %s",
                           getattr(sec, "name", "?"), exc)
    return out


def extract_pe_imports(binary, imphash: str) -> Optional[ImportFeatures]:
    """Extract imported DLLs and functions; flag suspicious APIs."""
    try:
        dlls: list[str] = []
        functions: list[tuple[str, str]] = []
        suspicious: list[str] = []

        for imp in binary.imports:
            dll = imp.name
            dlls.append(dll)
            for entry in imp.entries:
                fname = entry.name if not entry.is_ordinal else f"#ordinal_{entry.ordinal}"
                functions.append((dll, fname))
                if fname.rstrip("AW") in SUSPICIOUS_APIS or fname in SUSPICIOUS_APIS:
                    suspicious.append(f"{dll}!{fname}")

        return ImportFeatures(
            dlls=sorted(set(dlls)),
            functions=functions,
            imphash=imphash,
            n_imports=len(functions),
            suspicious_apis=sorted(set(suspicious)),
        )
    except Exception as exc:
        logger.warning("PE imports extraction failed: %s", exc)
        return None


def extract_pe_exports(binary) -> Optional[ExportFeatures]:
    """Extract exported functions (for DLLs)."""
    try:
        if not binary.has_exports:
            return None
        exp = binary.get_export()
        functions = [e.name for e in exp.entries if e.name]
        return ExportFeatures(
            dll_name=exp.name or None,
            functions=functions,
            n_exports=len(functions),
        )
    except Exception as exc:
        logger.warning("PE exports extraction failed: %s", exc)
        return None


def extract_pe_resources(binary) -> list[ResourceFeature]:
    """Walk the PE resource tree and collect leaf nodes."""
    out: list[ResourceFeature] = []
    try:
        if not binary.has_resources:
            return out
        manager = binary.resources_manager
        # Walk the raw resource tree for all leaf data
        def _walk(node, type_name: str = "?", name_path: str = ""):
            try:
                for child in node.childs:
                    cname = (
                        child.name if hasattr(child, "name") and child.name
                        else f"id_{child.id}" if hasattr(child, "id")
                        else "?"
                    )
                    if child.is_directory:
                        new_type = type_name if name_path else str(cname)
                        _walk(child, new_type, f"{name_path}/{cname}")
                    elif child.is_data:
                        try:
                            content = bytes(child.content)
                            out.append(ResourceFeature(
                                type=str(type_name),
                                name=name_path or str(cname),
                                language=int(getattr(child, "lang", 0)),
                                size=len(content),
                                entropy=shannon_entropy(content),
                                sha256=hashlib.sha256(content).hexdigest(),
                            ))
                        except Exception:
                            pass
            except Exception:
                pass

        if binary.resources is not None:
            _walk(binary.resources)
    except Exception as exc:
        logger.warning("PE resource extraction failed: %s", exc)
    return out


def extract_dotnet(data: bytes, binary) -> Optional[DotNetFeatures]:
    """
    Extract .NET metadata using dnfile (more complete than LIEF or pefile
    for managed binaries).
    """
    if not _has_clr_directory(binary):
        return None

    try:
        import dnfile
    except ImportError:
        logger.info("dnfile not installed; .NET features will be omitted")
        return DotNetFeatures()      # empty stub so caller knows it's .NET

    try:
        pe = dnfile.dnPE(data=data, fast_load=False)
        pe.parse_data_directories()
        net = pe.net
        if net is None:
            return DotNetFeatures()

        streams = []
        if net.metadata and net.metadata.streams:
            streams = list(net.metadata.streams.keys())

        assembly_name = None
        version = None
        revision = None
        guids: list[str] = []

        # Assembly table
        try:
            asm_table = net.mdtables.Assembly
            if asm_table and asm_table.rows:
                row = asm_table.rows[0]
                assembly_name = str(row.Name) if row.Name else None
                version = (f"{row.MajorVersion}.{row.MinorVersion}."
                            f"{row.BuildNumber}.{row.RevisionNumber}")
                revision = int(row.RevisionNumber)
        except Exception:
            pass

        # Module table — module name = DOTNET.NAME
        module_name = None
        try:
            mod_table = net.mdtables.Module
            if mod_table and mod_table.rows:
                row = mod_table.rows[0]
                module_name = str(row.Name) if row.Name else None
                if row.Mvid:
                    guids.append(str(row.Mvid))
        except Exception:
            pass

        # Type and method counts
        n_types = 0
        n_methods = 0
        n_strings = 0
        try:
            n_types = len(net.mdtables.TypeDef.rows) if net.mdtables.TypeDef else 0
            n_methods = len(net.mdtables.MethodDef.rows) if net.mdtables.MethodDef else 0
        except Exception:
            pass
        try:
            us_stream = net.metadata.streams.get(b"#US") or net.metadata.streams.get("#US")
            if us_stream:
                n_strings = len(getattr(us_stream, "strings", {}) or {})
        except Exception:
            pass

        # Try to find a TypeLib GUID from custom attributes
        typelib_id = None
        try:
            ca_table = net.mdtables.CustomAttribute
            if ca_table and ca_table.rows:
                for row in ca_table.rows:
                    val = bytes(getattr(row, "Value", b"") or b"")
                    if b"TypeLib" in val or b"typelib" in val:
                        # Extract first GUID-shaped substring
                        import re as _re
                        m = _re.search(
                            rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                            rb"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                            val,
                        )
                        if m:
                            typelib_id = m.group(0).decode("ascii")
                            break
        except Exception:
            pass

        return DotNetFeatures(
            assembly_name=assembly_name,
            module_name=module_name,
            version=version,
            revision_number=revision,
            streams=[s.decode("ascii", errors="ignore") if isinstance(s, bytes) else str(s)
                     for s in streams],
            typelib_id=typelib_id,
            guids=guids,
            n_types=n_types,
            n_methods=n_methods,
            n_strings=n_strings,
        )
    except Exception as exc:
        logger.warning(".NET extraction failed: %s", exc)
        return DotNetFeatures()


def compute_imphash(data: bytes) -> Optional[str]:
    """
    Imphash via pefile (LIEF's imphash equivalent has parity issues with
    Mandiant's reference implementation; pefile is the standard).
    """
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
        return pe.get_imphash() or None
    except Exception as exc:
        logger.info("Imphash unavailable: %s", exc)
        return None


def compute_authentihash(data: bytes) -> Optional[str]:
    """Authenticode hash (excludes signature block)."""
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        h = pe.get_authentihash() if hasattr(pe, "get_authentihash") else None
        if h:
            return h.hex() if isinstance(h, (bytes, bytearray)) else str(h)
    except Exception as exc:
        logger.info("Authentihash unavailable: %s", exc)
    return None


def compute_rich_pv_hash(data: bytes) -> Optional[str]:
    """Rich header PV hash — fingerprints build environment."""
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        rich = pe.parse_rich_header()
        if not rich:
            return None
        # Concatenate (id, version, count) tuples and hash
        values = rich.get("values", [])
        if not values:
            return None
        flat = b"".join(int(v).to_bytes(4, "little", signed=False)
                        for v in values if isinstance(v, int) and v >= 0)
        return hashlib.md5(flat).hexdigest()
    except Exception as exc:
        logger.info("Rich PV hash unavailable: %s", exc)
        return None


def parse_pe(data: bytes) -> Optional[object]:
    """Parse PE with LIEF; returns None if parsing fails entirely."""
    try:
        import lief
        # LIEF's logger is noisy — silence it for malformed samples
        try:
            lief.logging.disable()
        except Exception:
            pass
        binary = lief.PE.parse(list(data))
        return binary
    except ImportError as exc:
        logger.info("LIEF PE parser unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.warning("LIEF PE parse failed: %s", exc)
        return None


def extract_pe_fallback(data: bytes) -> tuple[Optional[PEHeaderFeatures], list[SectionFeature]]:
    """
    Lightweight PE header/section parser used when LIEF is unavailable.

    It intentionally extracts only stable structural fields needed by the
    schema and tests. Import/resource/.NET parsing stays with specialist
    libraries because partial parsers are easy to get subtly wrong there.
    """
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None, []
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset <= 0 or pe_offset + 24 > len(data):
            return None, []
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None, []

        coff_offset = pe_offset + 4
        (
            machine,
            n_sections,
            timestamp,
            _sym_ptr,
            _n_syms,
            opt_size,
            _chars,
        ) = struct.unpack_from("<HHIIIHH", data, coff_offset)

        opt_offset = coff_offset + 20
        section_table_offset = opt_offset + opt_size
        if opt_offset + opt_size > len(data):
            return None, []

        magic = struct.unpack_from("<H", data, opt_offset)[0] if opt_size >= 2 else 0
        is_pe32_plus = magic == 0x20B
        entry_point = _safe_unpack("<I", data, opt_offset + 16, 0)
        if is_pe32_plus:
            image_base = _safe_unpack("<Q", data, opt_offset + 24, 0)
            data_dir_offset = opt_offset + 112
        else:
            image_base = _safe_unpack("<I", data, opt_offset + 28, 0)
            data_dir_offset = opt_offset + 96
        subsystem = _safe_unpack("<H", data, opt_offset + 68, 0)
        dll_chars_value = _safe_unpack("<H", data, opt_offset + 70, 0)

        ts_iso = ""
        try:
            ts_iso = _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            ts_iso = "invalid"

        sections: list[SectionFeature] = []
        for idx in range(n_sections):
            sec_offset = section_table_offset + idx * 40
            if sec_offset + 40 > len(data):
                break
            raw_name = data[sec_offset:sec_offset + 8].split(b"\x00", 1)[0]
            name = raw_name.decode("utf-8", errors="replace").strip() or "<unnamed>"
            virtual_size, _virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, sec_offset + 8
            )
            characteristics_value = struct.unpack_from("<I", data, sec_offset + 36)[0]
            content = data[raw_offset:raw_offset + raw_size] if raw_offset < len(data) else b""
            ent = shannon_entropy(content)
            chars = _section_characteristics_from_bits(characteristics_value)
            pseudo_section = type("FallbackSection", (), {"name": name})()
            sections.append(SectionFeature(
                name=name,
                virtual_size=int(virtual_size),
                raw_size=int(raw_size),
                entropy=ent,
                md5=hashlib.md5(content).hexdigest() if content else "",
                characteristics=chars,
                is_executable="MEM_EXECUTE" in chars,
                is_writable="MEM_WRITE" in chars,
                is_readable="MEM_READ" in chars,
                suspicious=_is_suspicious_section(pseudo_section, ent, chars),
            ))

        header = PEHeaderFeatures(
            machine=_machine_name(machine),
            timestamp=int(timestamp),
            timestamp_iso=ts_iso,
            subsystem=_subsystem_name(subsystem),
            dll_characteristics=_dll_characteristics_from_bits(dll_chars_value),
            image_base=int(image_base),
            entry_point=int(entry_point),
            n_sections=int(n_sections),
            is_dotnet=_data_directory_present(data, data_dir_offset, 14),
            is_signed=_data_directory_present(data, data_dir_offset, 4),
            has_tls=_data_directory_present(data, data_dir_offset, 9),
            has_debug=_data_directory_present(data, data_dir_offset, 6),
            has_resources=_data_directory_present(data, data_dir_offset, 2),
            has_relocations=_data_directory_present(data, data_dir_offset, 5),
        )
        return header, sections
    except Exception as exc:
        logger.warning("PE fallback parser failed: %s", exc)
        return None, []


def _safe_unpack(fmt: str, data: bytes, offset: int, default: int) -> int:
    try:
        if offset + struct.calcsize(fmt) <= len(data):
            return int(struct.unpack_from(fmt, data, offset)[0])
    except Exception:
        pass
    return default


def _data_directory_present(data: bytes, data_dir_offset: int, index: int) -> bool:
    offset = data_dir_offset + index * 8
    if offset + 8 > len(data):
        return False
    rva, size = struct.unpack_from("<II", data, offset)
    return bool(rva and size)


def _section_characteristics_from_bits(value: int) -> list[str]:
    flags: list[str] = []
    known = {
        0x00000020: "CNT_CODE",
        0x00000040: "CNT_INITIALIZED_DATA",
        0x00000080: "CNT_UNINITIALIZED_DATA",
        0x02000000: "MEM_DISCARDABLE",
        0x04000000: "MEM_NOT_CACHED",
        0x08000000: "MEM_NOT_PAGED",
        0x10000000: "MEM_SHARED",
        0x20000000: "MEM_EXECUTE",
        0x40000000: "MEM_READ",
        0x80000000: "MEM_WRITE",
    }
    for bit, name in known.items():
        if value & bit:
            flags.append(name)
    return flags


def _dll_characteristics_from_bits(value: int) -> list[str]:
    known = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT",
        0x0200: "NO_ISOLATION",
        0x0400: "NO_SEH",
        0x0800: "NO_BIND",
        0x1000: "APPCONTAINER",
        0x2000: "WDM_DRIVER",
        0x4000: "GUARD_CF",
        0x8000: "TERMINAL_SERVER_AWARE",
    }
    return [name for bit, name in known.items() if value & bit]


def _machine_name(value: int) -> str:
    return {
        0x014C: "I386",
        0x8664: "AMD64",
        0x01C0: "ARM",
        0x01C4: "ARMNT",
        0xAA64: "ARM64",
    }.get(value, f"0x{value:04x}")


def _subsystem_name(value: int) -> str:
    return {
        0: "UNKNOWN",
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        7: "POSIX_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM",
        14: "XBOX",
        16: "WINDOWS_BOOT_APPLICATION",
    }.get(value, f"0x{value:04x}")

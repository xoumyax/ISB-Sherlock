"""Per-sample static feature extraction.

SAFETY (binding, IMPLEMENTATION_PLAN §0): every sample under the corpus root
(``ISB_DATA`` on ramius) is live malware. This module performs **static reads
only** -- ``open(path, "rb")`` and ``pefile`` parsing of an in-memory buffer.
Nothing here executes, chmod+x's, or extracts an archive, and nothing ever
should.

Robustness contract: :func:`extract_record` **never raises**. A truncated PE, a
hostile section table, a 4GB file, a pefile crash -- each yields a record with
whatever was recoverable plus an ``error`` string. One malformed sample must not
take down a 64k-file pass, and a partial record is still useful (the strings
usually survive a broken header).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import signal
import threading
from dataclasses import dataclass, field
from typing import Any

from .strings import MIN_STRING_LEN, extract_strings

__all__ = ["ExtractConfig", "extract_record", "record_schema_keys"]


@dataclass(frozen=True)
class ExtractConfig:
    """Extraction knobs (house style: overridden from the driver's CONFIG)."""

    min_string_len: int = MIN_STRING_LEN
    #: Per-encoding unique-string cap. Bounds cache size on packed blobs whose
    #: entropy makes every byte run look like a string.
    max_strings: int = 20_000
    #: Files above this are recorded with an error and no strings. 256MB of
    #: regex scanning per worker is not worth one sample.
    max_size_bytes: int = 256 * 1024 * 1024
    #: Per-file wall-clock budget, seconds. 0 disables.
    timeout_seconds: int = 120
    #: Extract imported function names in addition to DLL names.
    import_functions: bool = True
    #: Cap on imported function names (some packers import thousands).
    max_import_functions: int = 4_000
    #: Cap on export names.
    max_exports: int = 4_000


def record_schema_keys() -> tuple[str, ...]:
    """The record schema, as a stable contract for cache readers."""
    return (
        "sha256", "size", "is_pe", "strings_ascii", "strings_wide",
        "strings_truncated", "imports", "import_functions", "exports",
        "sections", "pe_original_filename", "pe_metadata", "imphash",
        "path", "error",
    )


class _Timeout(Exception):
    pass


@contextlib.contextmanager
def _time_limit(seconds: int):
    """SIGALRM-based wall-clock limit.

    Usable because extraction runs in ``multiprocessing.Pool`` workers, each the
    main thread of its own process. Degrades to a no-op off the main thread so
    the same code path works under pytest.
    """
    if seconds <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return

    def _handler(signum, frame):  # pragma: no cover - timing dependent
        raise _Timeout(f"timeout after {seconds}s")

    old = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _empty_record(path: str) -> dict[str, Any]:
    return {
        "sha256": None,
        "size": None,
        "is_pe": False,
        "strings_ascii": [],
        "strings_wide": [],
        "strings_truncated": False,
        "imports": [],
        "import_functions": [],
        "exports": [],
        "sections": [],
        "pe_original_filename": None,
        "pe_metadata": {},
        "imphash": None,
        "path": path,
        "error": None,
    }


def _decode(value: Any) -> str | None:
    """Best-effort text from pefile's bytes, tolerating hostile encodings."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value).strip("\x00").strip()
    return value or None


def _extract_pe(data: bytes, rec: dict[str, Any], config: ExtractConfig) -> None:
    """Fill the PE-derived fields in place.

    Each sub-extraction is independently guarded: a corrupt export table must
    not cost us the imports, and vice versa. Malformed-PE tolerance is the whole
    point -- packed malware routinely violates the spec.
    """
    import pefile  # local import: keeps module import cheap for cache readers

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"pe_parse:{type(exc).__name__}")
        return

    rec["is_pe"] = True
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ])
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"pe_dirs:{type(exc).__name__}")

    # -- sections ------------------------------------------------------
    try:
        sections = []
        for sec in getattr(pe, "sections", []) or []:
            name = _decode(sec.Name)
            sections.append({
                "name": name,
                "virtual_size": int(getattr(sec, "Misc_VirtualSize", 0) or 0),
                "raw_size": int(getattr(sec, "SizeOfRawData", 0) or 0),
                # File offset, so the classifier's window sampler can stratify
                # over sections without re-parsing the PE every epoch.
                "raw_ptr": int(getattr(sec, "PointerToRawData", 0) or 0),
            })
        rec["sections"] = sections
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"sections:{type(exc).__name__}")

    # -- imports + imphash --------------------------------------------
    try:
        dlls: list[str] = []
        funcs: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = _decode(getattr(entry, "dll", None))
            if dll:
                dlls.append(dll)
            if not config.import_functions:
                continue
            for imp in getattr(entry, "imports", []) or []:
                if len(funcs) >= config.max_import_functions:
                    break
                fn = _decode(getattr(imp, "name", None))
                if fn:
                    funcs.append(fn)
        rec["imports"] = sorted(set(dlls))
        rec["import_functions"] = sorted(set(funcs))
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"imports:{type(exc).__name__}")

    try:
        imphash = pe.get_imphash()
        rec["imphash"] = imphash.lower() if imphash else None
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"imphash:{type(exc).__name__}")

    # -- exports -------------------------------------------------------
    try:
        exports: list[str] = []
        direct = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        for sym in (getattr(direct, "symbols", []) or []) if direct else []:
            if len(exports) >= config.max_exports:
                break
            name = _decode(getattr(sym, "name", None))
            if name:
                exports.append(name)
        rec["exports"] = sorted(set(exports))
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"exports:{type(exc).__name__}")

    # -- version info --------------------------------------------------
    try:
        meta: dict[str, str] = {}
        for fileinfo in getattr(pe, "FileInfo", []) or []:
            entries = fileinfo if isinstance(fileinfo, list) else [fileinfo]
            for entry in entries:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in (getattr(st, "entries", {}) or {}).items():
                        key = _decode(k)
                        val = _decode(v)
                        if key and val:
                            meta[key] = val
        rec["pe_metadata"] = meta
        rec["pe_original_filename"] = meta.get("OriginalFilename")
    except Exception as exc:
        rec["error"] = _join_err(rec["error"], f"versioninfo:{type(exc).__name__}")

    with contextlib.suppress(Exception):
        pe.close()


def _join_err(existing: str | None, new: str) -> str:
    return f"{existing};{new}" if existing else new


def extract_record(
    path: str,
    config: ExtractConfig | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Extract one sample's static features. Never raises.

    ``expected_sha256`` (from the manifest) is verified rather than trusted: a
    mismatch is recorded as ``sha_mismatch`` in ``error``, because a cache keyed
    on a stale hash would silently mis-join every downstream statistic. The
    computed hash always wins as the record's identity.
    """
    config = config or ExtractConfig()
    rec = _empty_record(path)

    try:
        if not os.path.isfile(path):
            rec["error"] = "missing_file"
            return rec
        size = os.path.getsize(path)
        rec["size"] = size

        if size > config.max_size_bytes:
            rec["error"] = f"size_cap_exceeded:{size}"
            return rec

        with _time_limit(config.timeout_seconds):
            with open(path, "rb") as fh:          # static read only -- SAFETY
                data = fh.read()
            rec["sha256"] = hashlib.sha256(data).hexdigest()
            if expected_sha256 and rec["sha256"] != expected_sha256.lower():
                rec["error"] = _join_err(rec["error"], "sha_mismatch")

            rec.update(extract_strings(
                data, config.min_string_len, config.max_strings))

            if data[:2] == b"MZ":
                _extract_pe(data, rec, config)

    except _Timeout as exc:
        rec["error"] = _join_err(rec["error"], str(exc))
    except MemoryError:
        rec["error"] = _join_err(rec["error"], "memory_error")
    except Exception as exc:                      # never crash the pass
        rec["error"] = _join_err(rec["error"], f"{type(exc).__name__}:{exc}"[:200])

    return rec

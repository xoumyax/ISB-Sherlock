"""
Office document feature extractor.

Handles OLE (legacy .doc/.xls/.ppt) and OOXML (.docx/.xlsx/.pptx) plus RTF.
Macro extraction uses oletools (industry standard).
"""
from __future__ import annotations
import logging
from typing import Optional

from .schema import OfficeFeatures

logger = logging.getLogger(__name__)


# Triggers that auto-execute macros without user interaction
_AUTOEXEC_TRIGGERS = frozenset({
    "AutoOpen", "Auto_Open", "AutoExec", "AutoExit", "AutoClose", "Auto_Close",
    "Document_Open", "Document_Close", "DocumentOpen", "Workbook_Open",
    "Workbook_Activate", "Worksheet_Activate", "Worksheet_Change",
    "Workbook_BeforeClose", "Class_Initialize",
})

_MACRO_KEYWORDS = frozenset({
    "Shell", "WScript.Shell", "CreateObject", "GetObject",
    "Environ", "Chr", "Asc", "StrReverse", "Xor", "ExecuteGlobal",
    "ADODB.Stream", "MSXML2.XMLHTTP", "WinHttp.WinHttpRequest",
    "Scripting.FileSystemObject", "WScript.Network",
    "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta",
    "URLDownloadToFile", "VirtualAlloc", "RtlCopyMemory",
    "DownloadFile", "Run", "Exec",
})


def extract_office(data: bytes) -> Optional[OfficeFeatures]:
    """
    Extract Office document features. Requires `oletools` (olefile + olevba).

    Returns a minimal OfficeFeatures with file_format set even if oletools
    is unavailable, so callers can still see "this is Office".
    """
    file_format = _detect_office_format(data)

    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    except ImportError:
        logger.info("oletools not installed; Office macro detection disabled")
        return OfficeFeatures(
            file_format=file_format,
            has_macros=False,
        )

    try:
        vp = VBA_Parser("file.bin", data=data)
    except Exception as exc:
        logger.warning("oletools VBA_Parser failed to open: %s", exc)
        return OfficeFeatures(file_format=file_format, has_macros=False)

    try:
        has_macros = bool(vp.detect_vba_macros())
        macro_code: list[str] = []
        macro_langs: list[str] = []
        autoexec: list[str] = []
        suspicious: list[str] = []

        if has_macros:
            try:
                for (_filename, _stream, vba_filename, vba_code) in vp.extract_macros():
                    if vba_code:
                        macro_code.append(vba_code)
                        macro_langs.append("vba")
                        for trigger in _AUTOEXEC_TRIGGERS:
                            if trigger in vba_code:
                                autoexec.append(trigger)
                        for kw in _MACRO_KEYWORDS:
                            if kw in vba_code:
                                suspicious.append(kw)
            except Exception as exc:
                logger.warning("Macro code extraction failed: %s", exc)

        # XLM (Excel 4.0 macros) detection
        try:
            if vp.detect_xlm_macros():
                has_macros = True
                macro_langs.append("xlm")
        except Exception:
            pass

        # External relationship / DDE detection — requires additional parsing
        has_external = False
        has_dde = False
        embedded: list[str] = []

        try:
            # OOXML: scan for external links and DDE in the package XML
            if file_format == "ooxml":
                import zipfile
                import io
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for name in z.namelist():
                        lname = name.lower()
                        if "externallink" in lname or "external" in lname:
                            has_external = True
                        if name.endswith(".bin") or "embeddings" in lname:
                            embedded.append(name)
                        try:
                            content = z.read(name)
                            if b"DDEAUTO" in content or b"DDE " in content:
                                has_dde = True
                        except Exception:
                            continue
            elif file_format == "ole":
                # OLE: olefile can list streams
                try:
                    import io
                    import olefile
                    ole_stream = io.BytesIO(data)
                    if olefile.isOleFile(ole_stream):
                        ole_stream.seek(0)
                        ole = olefile.OleFileIO(ole_stream)
                        for stream in ole.listdir():
                            sname = "/".join(stream)
                            if "ObjectPool" in sname or "Embedded" in sname:
                                embedded.append(sname)
                        ole.close()
                except Exception:
                    pass
        except Exception as exc:
            logger.info("Extended Office parsing failed: %s", exc)

        return OfficeFeatures(
            file_format=file_format,
            has_macros=has_macros,
            macro_languages=sorted(set(macro_langs)),
            macro_code=macro_code,
            has_external_refs=has_external,
            has_dde=has_dde,
            suspicious_keywords=sorted(set(suspicious)),
            embedded_objects=sorted(set(embedded)),
            autoexec_triggers=sorted(set(autoexec)),
        )
    except Exception as exc:
        logger.warning("Office feature extraction failed: %s", exc)
        return OfficeFeatures(file_format=file_format, has_macros=False)
    finally:
        try:
            vp.close()
        except Exception:
            pass


def _detect_office_format(data: bytes) -> str:
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:4] == b"PK\x03\x04":
        return "ooxml"
    if data[:5] == b"{\\rtf" or data[:6] == b"{\\rtf1":
        return "rtf"
    return "unknown"

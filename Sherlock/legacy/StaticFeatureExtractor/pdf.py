"""
PDF feature extractor.

Focuses on weaponization indicators (JavaScript, OpenAction, Launch,
embedded files) rather than rendered text. Uses pikepdf as primary parser
with a regex fallback for malformed PDFs that no parser will accept.
"""
from __future__ import annotations
import logging
import re
from typing import Optional

from .schema import PDFFeatures

logger = logging.getLogger(__name__)


# Suspicious keywords that map to PDF action types
_SUSPICIOUS_KEYWORDS = [
    "/JavaScript", "/JS",
    "/OpenAction", "/AA",
    "/Launch", "/SubmitForm", "/ImportData",
    "/EmbeddedFile", "/EmbeddedFiles",
    "/RichMedia", "/Flash",
    "/XFA",
    "/URI",
    "/GoToE", "/GoToR",
]


def extract_pdf(data: bytes) -> Optional[PDFFeatures]:
    """Extract PDF features. Tries pikepdf first, falls back to regex scan."""
    parsed = _try_pikepdf(data)
    if parsed is not None:
        return parsed
    return _regex_fallback(data)


def _try_pikepdf(data: bytes) -> Optional[PDFFeatures]:
    try:
        import pikepdf
        import io
    except ImportError:
        logger.info("pikepdf not installed; using regex fallback for PDF")
        return None

    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except Exception as exc:
        logger.warning("pikepdf failed to open PDF: %s; falling back to regex", exc)
        return None

    try:
        n_pages = len(pdf.pages)
        root = pdf.Root

        has_js = False
        has_openaction = False
        has_launch = False
        has_embedded = False
        has_forms = False

        embedded_files: list[str] = []
        js_blobs: list[str] = []
        suspicious: list[str] = []

        # OpenAction at document level
        try:
            if "/OpenAction" in root:
                has_openaction = True
                suspicious.append("/OpenAction")
                action = root["/OpenAction"]
                if isinstance(action, pikepdf.Dictionary):
                    if "/S" in action and str(action["/S"]) == "/JavaScript":
                        has_js = True
                    if "/JS" in action:
                        has_js = True
                        try:
                            js_blobs.append(_truncate(str(action["/JS"]), 500))
                        except Exception:
                            pass
                    if "/S" in action and str(action["/S"]) == "/Launch":
                        has_launch = True
        except Exception:
            pass

        # Document-level Names tree
        try:
            if "/Names" in root:
                names = root["/Names"]
                if "/JavaScript" in names:
                    has_js = True
                    suspicious.append("/JavaScript")
                if "/EmbeddedFiles" in names:
                    has_embedded = True
                    suspicious.append("/EmbeddedFiles")
                    try:
                        ef_tree = names["/EmbeddedFiles"]
                        if "/Names" in ef_tree:
                            for entry in ef_tree["/Names"]:
                                if isinstance(entry, str):
                                    embedded_files.append(entry)
                    except Exception:
                        pass
        except Exception:
            pass

        # AcroForm
        try:
            if "/AcroForm" in root:
                has_forms = True
                af = root["/AcroForm"]
                if "/XFA" in af:
                    suspicious.append("/XFA")
        except Exception:
            pass

        # Page-level scan for /AA, /Launch, etc.
        for page in pdf.pages:
            try:
                if "/AA" in page:
                    suspicious.append("/AA")
                # Annotations can carry /Launch and /URI
                if "/Annots" in page:
                    for annot in page["/Annots"]:
                        try:
                            a = annot.get("/A", None) if hasattr(annot, "get") else None
                            if a is None:
                                continue
                            s_type = str(a.get("/S", "")) if hasattr(a, "get") else ""
                            if s_type == "/Launch":
                                has_launch = True
                                suspicious.append("/Launch")
                            elif s_type == "/JavaScript":
                                has_js = True
                                suspicious.append("/JavaScript")
                                if "/JS" in a:
                                    js_blobs.append(_truncate(str(a["/JS"]), 500))
                            elif s_type == "/URI" and "/URI" in a:
                                suspicious.append(f"/URI:{_truncate(str(a['/URI']), 200)}")
                        except Exception:
                            continue
            except Exception:
                continue

        return PDFFeatures(
            n_pages=n_pages,
            has_javascript=has_js,
            has_embedded_files=has_embedded,
            has_openaction=has_openaction,
            has_launch=has_launch,
            has_forms=has_forms,
            suspicious_keywords=sorted(set(suspicious)),
            embedded_files=sorted(set(embedded_files)),
            javascript_blobs=js_blobs[:10],
        )
    except Exception as exc:
        logger.warning("pikepdf walk failed: %s; using regex fallback", exc)
        return _regex_fallback(data)
    finally:
        try:
            pdf.close()
        except Exception:
            pass


def _regex_fallback(data: bytes) -> PDFFeatures:
    """When no PDF parser will accept the file, scan the raw bytes."""
    suspicious: list[str] = []
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw.encode("ascii") in data:
            suspicious.append(kw)

    n_pages = data.count(b"/Type /Page") - data.count(b"/Type /Pages")
    if n_pages < 0:
        n_pages = 0

    return PDFFeatures(
        n_pages=n_pages,
        has_javascript=any(k in suspicious for k in ("/JavaScript", "/JS")),
        has_embedded_files="/EmbeddedFile" in suspicious or "/EmbeddedFiles" in suspicious,
        has_openaction="/OpenAction" in suspicious,
        has_launch="/Launch" in suspicious,
        has_forms="/XFA" in suspicious,
        suspicious_keywords=sorted(set(suspicious)),
        embedded_files=[],
        javascript_blobs=[],
    )


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + "..."

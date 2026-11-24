"""
Format-agnostic utilities: hashing, entropy, byte stats, string extraction,
file typing.
"""
from __future__ import annotations
import hashlib
import logging
import math
import re
from collections import Counter
from pathlib import Path
from typing import Optional

from .schema import (
    HashFeatures,
    FileTypeFeatures,
    FileFormat,
    StringFeatures,
    ByteHistogramFeatures,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
#  Hashing
# ──────────────────────────────────────────────────────────────────────

def compute_hashes(data: bytes) -> HashFeatures:
    """Compute the always-available hashes. Format-specific hashes
    (imphash, telfhash) are filled in by the format extractors."""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # SSDEEP is optional — fall back gracefully if not installed
    ssdeep_hash = ""
    try:
        import ssdeep as _ssdeep
        ssdeep_hash = _ssdeep.hash(data)
    except ImportError:
        logger.info("ssdeep not installed; SSDEEP hash will be empty")
    except Exception as exc:
        logger.warning("ssdeep failed: %s", exc)

    return HashFeatures(md5=md5, sha1=sha1, sha256=sha256, ssdeep=ssdeep_hash)


# ──────────────────────────────────────────────────────────────────────
#  Entropy + byte histograms (EMBER-style)
# ──────────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. Returns 0.0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def byte_histogram(data: bytes) -> list[int]:
    """256-bin byte frequency histogram."""
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    return hist


def byte_entropy_histogram(data: bytes, window_size: int = 2048,
                            step: int = 1024) -> list[float]:
    """
    EMBER's 2D byte-entropy histogram, flattened to 256-d.
    16 entropy bins × 16 byte-value bins, weighted by window count.

    For small files (< window_size), returns a uniform low-entropy histogram.
    """
    if len(data) < window_size:
        # Pad with a single global window to keep output shape stable
        windows = [data]
    else:
        windows = [data[i:i + window_size]
                   for i in range(0, len(data) - window_size + 1, step)]

    hist = [[0.0] * 16 for _ in range(16)]   # 16 entropy × 16 byte bins

    for window in windows:
        if not window:
            continue
        ent = shannon_entropy(window)
        ent_bin = min(int(ent * 2), 15)      # entropy 0..8 → bin 0..15
        # Per-window byte distribution into 16 coarse bins
        win_hist = [0] * 16
        for b in window:
            win_hist[b >> 4] += 1
        total = sum(win_hist)
        if total > 0:
            for i, c in enumerate(win_hist):
                hist[ent_bin][i] += c / total

    flat = [v for row in hist for v in row]
    return flat


def compute_byte_features(data: bytes) -> ByteHistogramFeatures:
    return ByteHistogramFeatures(
        histogram=byte_histogram(data),
        entropy=shannon_entropy(data),
        byte_entropy_histogram=byte_entropy_histogram(data),
    )


# ──────────────────────────────────────────────────────────────────────
#  File typing (libmagic + Magika)
# ──────────────────────────────────────────────────────────────────────

# Format dispatch — used by the orchestrator to pick the format-specific
# extractor. Order matters: more specific patterns first.
_MAGIKA_TO_FORMAT: dict[str, FileFormat] = {
    "pebin": FileFormat.PE, "peexe": FileFormat.PE, "pedll": FileFormat.PE,
    "elfbin": FileFormat.ELF, "elf": FileFormat.ELF,
    "macho": FileFormat.MACHO,
    "javascript": FileFormat.SCRIPT, "powershell": FileFormat.SCRIPT,
    "vba": FileFormat.SCRIPT, "vbs": FileFormat.SCRIPT,
    "python": FileFormat.SCRIPT, "shell": FileFormat.SCRIPT,
    "batch": FileFormat.SCRIPT, "perl": FileFormat.SCRIPT,
    "ruby": FileFormat.SCRIPT,
    "doc": FileFormat.OFFICE, "docx": FileFormat.OFFICE,
    "xls": FileFormat.OFFICE, "xlsx": FileFormat.OFFICE,
    "ppt": FileFormat.OFFICE, "pptx": FileFormat.OFFICE,
    "rtf": FileFormat.OFFICE, "ole2": FileFormat.OFFICE,
    "pdf": FileFormat.PDF,
}


def detect_file_type(path: Path, data: bytes) -> FileTypeFeatures:
    """
    Detect file type via libmagic and Magika. Magika is preferred for
    routing; libmagic is preserved as an IOC value.
    """
    libmagic_result = ""
    try:
        import magic
        libmagic_result = magic.from_buffer(data) if data else "empty"
    except ImportError:
        logger.info("python-magic not installed")
    except Exception as exc:
        logger.warning("libmagic failed: %s", exc)

    magika_label = "unknown"
    magika_score = 0.0
    detected_format = FileFormat.UNKNOWN

    try:
        from magika import Magika
        m = Magika()
        result = m.identify_bytes(data)
        # Magika's API has shifted across versions:
        #   < 0.6: result.output.ct_label, result.output.score
        #   >= 0.6: result.output.label, result.score (top-level)
        # Try the new names first, fall back to the old.
        try:
            magika_label = result.output.label
        except AttributeError:
            magika_label = result.output.ct_label
        try:
            magika_score = float(result.score)
        except AttributeError:
            try:
                magika_score = float(result.output.score)
            except AttributeError:
                magika_score = 1.0       # unknown; assume confident
        detected_format = _MAGIKA_TO_FORMAT.get(magika_label, FileFormat.UNKNOWN)
        # Magika can mislabel small/atypical samples (e.g., bare ELF headers
        # with no program data are sometimes labeled "iso"). When the label
        # maps to UNKNOWN, fall through to magic-byte detection — the magic
        # signatures are unambiguous and don't depend on file contents
        # beyond the first few bytes.
        if detected_format == FileFormat.UNKNOWN:
            magic_byte_format = _format_from_libmagic(libmagic_result, data, path)
            if magic_byte_format != FileFormat.UNKNOWN:
                detected_format = magic_byte_format
    except ImportError:
        logger.info("magika not installed; falling back to libmagic-only detection")
        detected_format = _format_from_libmagic(libmagic_result, data, path)
    except Exception as exc:
        logger.warning("Magika failed: %s", exc)
        detected_format = _format_from_libmagic(libmagic_result, data, path)

    return FileTypeFeatures(
        libmagic=libmagic_result,
        magika=magika_label,
        magika_score=magika_score,
        file_size=len(data),
        detected_format=detected_format,
    )


def _format_from_libmagic(magic_str: str, data: bytes, path: Optional[Path] = None) -> FileFormat:
    """Fallback format detection when Magika is unavailable."""
    s = magic_str.lower()
    suffix = path.suffix.lower() if path else ""
    if data[:2] == b"MZ" or "pe32" in s or "ms-dos" in s:
        return FileFormat.PE
    if data[:4] == b"\x7fELF":
        return FileFormat.ELF
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                     b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                     b"\xca\xfe\xba\xbe"):
        return FileFormat.MACHO
    if data[:4] == b"%PDF":
        return FileFormat.PDF
    if data[:4] == b"PK\x03\x04" and ("openxml" in s or "office" in s):
        return FileFormat.OFFICE
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return FileFormat.OFFICE
    if suffix in {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx", ".rtf"}:
        return FileFormat.OFFICE
    if suffix in {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".py", ".sh", ".bash", ".bat", ".cmd", ".pl", ".rb"}:
        return FileFormat.SCRIPT
    sample = data[:4096].lower()
    if sample.startswith(b"#!") or b"invoke-expression" in sample or b"new-object" in sample:
        return FileFormat.SCRIPT
    if b"wscript.shell" in sample or b"activexobject" in sample:
        return FileFormat.SCRIPT
    if any(k in s for k in ("script", "shell", "python", "perl", "ruby")):
        return FileFormat.SCRIPT
    return FileFormat.UNKNOWN


# ──────────────────────────────────────────────────────────────────────
#  String extraction
# ──────────────────────────────────────────────────────────────────────

# Regexes for IOC-shaped strings inside extracted text
_URL_RE = re.compile(rb"https?://[^\s<>\"']{4,512}")
_IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    rb"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}")
_WIN_PATH_RE = re.compile(
    rb"[A-Za-z]:\\(?:[^\x00-\x1f\\/:*?\"<>|]{1,255}\\)*[^\x00-\x1f\\/:*?\"<>|]{0,255}"
)
_UNIX_PATH_RE = re.compile(rb"/(?:[A-Za-z0-9._\-]+/){1,16}[A-Za-z0-9._\-]{1,255}")
_REGISTRY_RE = re.compile(
    rb"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|"
    rb"HKLM|HKCU|HKCR|HKU|HKCC)\\(?:[^\x00-\x1f\\]{1,255}\\?){1,16}"
)


def extract_strings(data: bytes, min_length: int = 6) -> list[bytes]:
    """
    Extract printable ASCII and UTF-16LE strings of at least min_length chars.
    Mirrors GNU `strings -a -n N` for ASCII plus a wide-string pass.
    """
    out: list[bytes] = []
    # ASCII strings
    ascii_pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    out.extend(ascii_pat.findall(data))
    # UTF-16LE: printable byte followed by null
    utf16_pat = re.compile(
        rb"(?:[\x20-\x7e]\x00){%d,}" % min_length
    )
    for match in utf16_pat.findall(data):
        try:
            decoded = match.decode("utf-16-le").encode("ascii", errors="ignore")
            if len(decoded) >= min_length:
                out.append(decoded)
        except UnicodeDecodeError:
            continue
    return out


def compute_string_features(data: bytes, use_floss: bool = False) -> StringFeatures:
    """
    Extract strings and derive IOC candidates. If use_floss=True, attempt
    FLOSS deobfuscation for stack/decoded strings (slow; opt-in).
    """
    strings = extract_strings(data)
    floss_used = False

    if use_floss:
        floss_strings = _try_floss(data)
        if floss_strings is not None:
            strings.extend(floss_strings)
            floss_used = True

    if not strings:
        return StringFeatures(
            n_strings=0, n_urls=0, n_paths=0, n_registry_keys=0, n_ips=0,
            avg_length=0.0, entropy=0.0, printable_ratio=0.0,
            floss_used=floss_used,
        )

    blob = b"\n".join(strings)

    urls = sorted({m.decode("ascii", errors="ignore")
                   for m in _URL_RE.findall(blob)})
    ips = sorted({m.decode("ascii", errors="ignore")
                  for m in _IP_RE.findall(blob)})
    emails = sorted({m.decode("ascii", errors="ignore")
                     for m in _EMAIL_RE.findall(blob)})
    win_paths = {m.decode("ascii", errors="ignore")
                 for m in _WIN_PATH_RE.findall(blob)}
    unix_paths = {m.decode("ascii", errors="ignore")
                  for m in _UNIX_PATH_RE.findall(blob)}
    paths = sorted(win_paths | unix_paths)
    regs = sorted({m.decode("ascii", errors="ignore")
                   for m in _REGISTRY_RE.findall(blob)})

    avg_len = sum(len(s) for s in strings) / len(strings)
    printable_count = sum(
        1 for b in blob
        if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d)
    )
    printable_ratio = printable_count / len(blob) if blob else 0.0

    return StringFeatures(
        n_strings=len(strings),
        n_urls=len(urls),
        n_paths=len(paths),
        n_registry_keys=len(regs),
        n_ips=len(ips),
        avg_length=avg_len,
        entropy=shannon_entropy(blob),
        printable_ratio=printable_ratio,
        paths=paths,
        registry_keys=regs,
        urls=urls,
        ips=ips,
        emails=emails,
        floss_used=floss_used,
    )


def _try_floss(data: bytes) -> Optional[list[bytes]]:
    """
    Run FLOSS for deobfuscated/stack strings. FLOSS requires a file on disk
    and is slow (5–60s per binary). Returns None if FLOSS is unavailable.
    """
    try:
        import tempfile
        import subprocess
        import json as _json

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(data)
            tf_path = tf.name

        try:
            result = subprocess.run(
                ["floss", "--json", "--no", "static", tf_path],
                capture_output=True, timeout=120, check=False,
            )
            if result.returncode != 0:
                logger.warning("FLOSS exited %d: %s",
                               result.returncode, result.stderr[:200])
                return None
            parsed = _json.loads(result.stdout)
            collected: list[bytes] = []
            for key in ("stack_strings", "tight_strings", "decoded_strings"):
                for s in parsed.get("strings", {}).get(key, []):
                    val = s.get("string") if isinstance(s, dict) else s
                    if isinstance(val, str):
                        collected.append(val.encode("utf-8", errors="ignore"))
            return collected
        finally:
            Path(tf_path).unlink(missing_ok=True)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.info("FLOSS not available or timed out; skipping deobfuscation pass")
        return None
    except Exception as exc:
        logger.warning("FLOSS extraction failed: %s", exc)
        return None

"""
Script/text-file feature extractor.

Handles PowerShell (.ps1), VBScript (.vbs), JavaScript (.js), Python (.py),
shell scripts (.sh, .bash), batch files (.bat/.cmd), and other text-based
formats.  All imports are optional; falls back gracefully if unavailable.
"""
from __future__ import annotations

import base64
import math
import re
from typing import Optional

from .schema import ScriptFeatures

# ── Suspicious keyword sets per language ─────────────────────────────────────

_PS1_SUSPICIOUS = {
    "invoke-expression", "iex", "invoke-webrequest", "downloadstring",
    "encodedcommand", "-enc", "-e ", "-nop", "-noninteractive", "-noprofile",
    "hidden", "bypass", "unrestricted", "downloadfile", "net.webclient",
    "shellcode", "virtualalloc", "createthread", "loadlibrary",
    "reflection.assembly", "frombase64string", "convertto-securestring",
    "add-type", "start-process", "set-executionpolicy", "get-wmiobject",
    "invoke-mimikatz", "invoke-shellcode", "amsibypass", "amsi",
}

_VBS_SUSPICIOUS = {
    "wscript.shell", "createobject", "shell.application", "run",
    "regwrite", "powershell", "downloadfile", "xmlhttp", "msxml2",
    "adodb.stream", "chr(", "charcode", "exec", "shellexecute",
}

_JS_SUSPICIOUS = {
    "activexobject", "wscript", "xmlhttprequest", "xmlhttp",
    "adodb.stream", "powershell", "eval(", "unescape(", "fromcharcode",
    "document.write", "location.href", "exec",
}

_GENERAL_SUSPICIOUS = {
    "base64", "shellcode", "payload", "exploit", "meterpreter",
    "cobalt strike", "cobaltstrike", "beacon", "download",
    "http://", "https://", "wget", "curl -", "invoke-", "cmd /c",
    "cmd.exe", "powershell.exe",
}

_PS1_FLAGS = {
    "-encodedcommand", "-enc", "-e", "-noninteractive", "-nop", "-noprofile",
    "-hidden", "-bypass", "-unrestricted", "-windowstyle", "-executionpolicy",
    "-command",
}

_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_URL_RE = re.compile(
    r'https?://[^\s\'"<>]{4,200}',
    re.IGNORECASE,
)

_LANG_MAP: dict[str, str] = {
    "ps1":  "powershell",
    "vbs":  "vbscript",
    "vbe":  "vbscript",
    "js":   "javascript",
    "jse":  "javascript",
    "py":   "python",
    "sh":   "shell",
    "bash": "shell",
    "bat":  "batch",
    "cmd":  "batch",
}

_SHEBANG_LANG: dict[str, str] = {
    "python":  "python",
    "bash":    "shell",
    "sh":      "shell",
    "node":    "javascript",
    "perl":    "perl",
    "ruby":    "ruby",
    "php":     "php",
}


def extract_script(data: bytes, *, magika_hint: Optional[str] = None) -> ScriptFeatures:
    """
    Extract script/text features from raw bytes.

    Args:
        data:         Raw file bytes.
        magika_hint:  Magika's file-type label (used to determine language).
    """
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    language = _detect_language(text, magika_hint)
    lines = text.splitlines()
    line_count = len(lines)
    char_count = len(text)
    avg_line_length = (char_count / line_count) if line_count else 0.0
    entropy = _shannon_entropy(data)

    suspicious_keywords = _find_suspicious(text, language)
    base64_blobs = _extract_base64(text)
    urls = _URL_RE.findall(text)[:40]
    ps_flags = _extract_ps_flags(text) if language == "powershell" else []
    obfuscation_score = _compute_obfuscation_score(
        text, language, base64_blobs, suspicious_keywords
    )

    return ScriptFeatures(
        language=language,
        line_count=line_count,
        char_count=char_count,
        avg_line_length=round(avg_line_length, 2),
        entropy=round(entropy, 4),
        obfuscation_score=round(obfuscation_score, 4),
        suspicious_keywords=suspicious_keywords[:64],
        base64_blobs=[b[:64] for b in base64_blobs[:16]],
        urls=urls,
        powershell_flags=ps_flags,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_language(text: str, hint: Optional[str]) -> str:
    if hint:
        lang = _LANG_MAP.get(hint.lower().strip("."))
        if lang:
            return lang
        # Magika sometimes returns labels like "powershell", "javascript" directly
        if hint.lower() in {"powershell", "vbscript", "javascript", "python", "shell", "batch", "perl"}:
            return hint.lower()

    # Shebang detection
    first_line = text.split("\n", 1)[0].strip()
    if first_line.startswith("#!"):
        for key, lang in _SHEBANG_LANG.items():
            if key in first_line.lower():
                return lang

    # Content heuristics
    lower = text[:2048].lower()
    if "$env:" in lower or "param(" in lower or "function " in lower and "powershell" in lower:
        return "powershell"
    if "wscript.shell" in lower or "createobject" in lower:
        return "vbscript"
    if "activexobject" in lower or "document.write" in lower:
        return "javascript"
    if "def " in lower and "import " in lower:
        return "python"
    if "@echo off" in lower or "endlocal" in lower:
        return "batch"

    return "unknown"


def _find_suspicious(text: str, language: str) -> list[str]:
    lower = text.lower()
    hits: list[str] = []
    keyword_sets = [_GENERAL_SUSPICIOUS]
    if language == "powershell":
        keyword_sets.append(_PS1_SUSPICIOUS)
    elif language == "vbscript":
        keyword_sets.append(_VBS_SUSPICIOUS)
    elif language == "javascript":
        keyword_sets.append(_JS_SUSPICIOUS)

    seen: set[str] = set()
    for kw_set in keyword_sets:
        for kw in kw_set:
            if kw in lower and kw not in seen:
                hits.append(kw)
                seen.add(kw)
    return hits


def _extract_base64(text: str) -> list[str]:
    blobs: list[str] = []
    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        try:
            base64.b64decode(candidate + "==")
            blobs.append(candidate)
        except Exception:
            pass
    return blobs


def _extract_ps_flags(text: str) -> list[str]:
    lower = text.lower()
    return [flag for flag in _PS1_FLAGS if flag in lower]


def _compute_obfuscation_score(
    text: str,
    language: str,
    base64_blobs: list[str],
    suspicious_keywords: list[str],
) -> float:
    score = 0.0

    # Base64 density
    if base64_blobs:
        score += min(0.35, len(base64_blobs) * 0.07)

    # PowerShell -enc / -EncodedCommand is almost always obfuscation
    if language == "powershell" and any("-enc" in kw.lower() for kw in suspicious_keywords):
        score += 0.30

    # High ratio of non-printable / special characters
    if text:
        special = sum(1 for c in text if not (c.isalnum() or c in " \t\n\r.,;:()[]{}\"'_-+="))
        score += min(0.25, (special / len(text)) * 4)

    # Very long lines (often indicate base64 or compressed payloads)
    lines = text.splitlines()
    if lines:
        max_len = max((len(ln) for ln in lines), default=0)
        if max_len > 500:
            score += 0.10
        if max_len > 2000:
            score += 0.10

    # chr() / charcode calls (character-based encoding)
    chr_count = text.lower().count("chr(")
    score += min(0.20, chr_count * 0.02)

    return min(1.0, score)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)

"""Curated always-active stoplist for candidate hygiene.

Why this exists rather than relying on the goodware DF index alone (HANDOFF
lesson): the most catastrophic generic candidates -- generic PE section names --
are *shorter than the DF index's minimum string length*, so they are invisible
to DF statistics and sail through into rules that match every PE on disk. The
curated list is therefore active in every arm including ``all``-adjacent
hygiene, and is not a tunable.

Matching is on ``Candidate.norm`` (case-folded) and is type-aware: a section
stoplist entry must not silently kill a string candidate that happens to spell
``.text``, and vice versa.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .candidate import CType, Candidate

__all__ = [
    "GENERIC_SECTIONS",
    "PACKER_SECTIONS",
    "SYSTEM_DLLS",
    "SYSTEM_DLL_PATTERNS",
    "BOILERPLATE_SUBSTRINGS",
    "UNIVERSAL_IMPORTS",
    "RUNTIME_IMPORTS",
    "RUNTIME_IMPORT_PATTERNS",
    "DOTNET_RUNTIME_SUBSTRINGS",
    "MARSHALLING_SUBSTRINGS",
    "MIN_DECODED_FRAGMENT",
    "Stoplist",
    "trivial_hex_reason",
    "MIN_HEX_DISTINCT_BYTES",
    "MAX_HEX_NULL_FRAC",
]


#: Sections present in essentially every compiled PE.
GENERIC_SECTIONS = frozenset({
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc",
    ".tls", ".pdata", ".xdata", ".debug", ".didat", ".sxdata", ".gfids",
    ".crt", ".00cfg", ".detourc", ".detourd", ".shared", "code", "data",
    ".ndata", ".rodata", ".eh_fram", ".textbss", ".drectve", ".symtab",
})

#: Packer/protector sections. Generic *across families* -- they identify the
#: packer, not the malware, so they are FP engines for family rules.
PACKER_SECTIONS = frozenset({
    "upx0", "upx1", "upx2", "upx!", ".upx0", ".upx1", ".upx2",
    ".aspack", ".adata", ".asdata", ".themida", ".winlice", ".vmp0", ".vmp1",
    ".vmp2", ".petite", ".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "nsp2",
    ".mpress1", ".mpress2", ".pklstb", "pebundle", ".yp", ".y0da", ".boom",
    ".enigma1", ".enigma2", ".mackt", ".neolit", ".perplex", ".packed",
    ".rlpack", ".rpcrypt", ".seau", ".sforce3", ".shrink1", ".spack",
    ".svkp", ".taz", ".tsuarch", ".tsustub", ".vprotect", ".wwp32", ".wwpack",
    "dsstext", "kkrunchy", "tsuarch", "petite",
})

#: Windows system libraries. Their presence is universal, not discriminative.
SYSTEM_DLLS = frozenset({
    "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll",
    "msvcrt.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll", "shell32.dll",
    "gdi32.dll", "gdi32full.dll", "ws2_32.dll", "wsock32.dll", "wininet.dll",
    "urlmon.dll", "shlwapi.dll", "comctl32.dll", "comdlg32.dll",
    "version.dll", "crypt32.dll", "psapi.dll", "rpcrt4.dll", "setupapi.dll",
    "mscoree.dll", "mscorlib.dll", "winmm.dll", "imm32.dll", "sechost.dll",
    "combase.dll", "bcrypt.dll", "bcryptprimitives.dll", "ucrtbase.dll",
    "shcore.dll", "iphlpapi.dll", "netapi32.dll", "userenv.dll", "winspool.drv",
    "oledlg.dll", "uxtheme.dll", "dwmapi.dll", "propsys.dll", "cfgmgr32.dll",
})

#: Versioned runtime libraries -- regex because the version digits vary.
SYSTEM_DLL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^msvcp\d+d?\.dll$"),
    re.compile(r"^msvcr\d+d?\.dll$"),
    re.compile(r"^vcruntime\d+(_\d+)?d?\.dll$"),
    re.compile(r"^ucrtbased?\.dll$"),
    re.compile(r"^api-ms-win-.*\.dll$"),
    re.compile(r"^ext-ms-win-.*\.dll$"),
    re.compile(r"^mfc\d+u?d?\.dll$"),
    re.compile(r"^d3dx?\d+(_\d+)?\.dll$"),
    re.compile(r"^qt\d?(core|gui|widgets|network)\d*\.dll$"),
)

#: Compiler/linker/runtime boilerplate that appears verbatim in most binaries.
#: Matched as substrings, because it is usually embedded in a longer string.
BOILERPLATE_SUBSTRINGS: tuple[str, ...] = (
    "this program cannot be run in dos mode",
    "this program must be run under win32",
    "!this program",
    ".?av",
    "std::",
    "operator new",
    "operator delete",
    "__cdecl",
    "__stdcall",
    "__thiscall",
    "microsoft visual c++ runtime library",
    "runtime error!",
    "program:",
    "- attempt to initialize the crt more than once",
    "- crt not initialized",
    "- floating point support not loaded",
    "- not enough space for arguments",
    "- not enough space for locale information",
    "- pure virtual function call",
    "- unable to initialize heap",
    "abnormal program termination",
    "gnu c++",
    "libgcj",
    "assertion failed",
    "invalid parameter passed to c runtime",
    "unknown exception",
    "bad allocation",
    ".idata$",
    ".rdata$",
    "borland c++ - copyright",
    "installshield",
    "nullsoft install system",
    "inno setup",
    "python27.dll",
    "sqlite format",
    "<?xml version=",
    "<assembly xmlns=",
    "urn:schemas-microsoft-com:asm",
    "requestedexecutionlevel",
    "microsoft.windows.common-controls",
    "http://www.w3.org/",
    "http://schemas.xmlsoap.org/",
    "http://crl.microsoft.com/",
    "http://www.microsoft.com/",
    "http://ocsp.digicert.com",
    "http://crl3.digicert.com",
    "http://crl4.digicert.com",
    "verisign",
    "thawte",
    "globalsign",
    "digicert",
    "sectigo",
    "comodo ca limited",
)

#: The handful of imports so universal they carry no signal at all. Kept short
#: on purpose -- genuinely suspicious APIs (VirtualAlloc, CreateRemoteThread)
#: are left to the DF index and the scorer, which can weigh them in context.
UNIVERSAL_IMPORTS = frozenset({
    "loadlibrarya", "loadlibraryw", "getprocaddress", "getmodulehandlea",
    "getmodulehandlew", "exitprocess", "getlasterror", "setlasterror",
    "getcommandlinea", "getcommandlinew", "getstartupinfoa", "getstartupinfow",
    "getcurrentprocess", "getcurrentprocessid", "getcurrentthreadid",
    "getsystemtimeasfiletime", "queryperformancecounter",
    "gettickcount", "gettickcount64",
    "initializecriticalsection", "deletecriticalsection",
    "entercriticalsection", "leavecriticalsection",
    "heapalloc", "heapfree", "getprocessheap", "closehandle",
    "multibytetowidechar", "widechartomultibyte", "rtladdfunctiontable",
    "rtlcapturecontext", "rtllookupfunctionentry", "rtlvirtualunwind",
    "unhandledexceptionfilter", "setunhandledexceptionfilter",
    "terminateprocess", "isdebuggerpresent", "isprocessorfeaturepresent",
    "encodepointer", "decodepointer",
})

#: Runtime-language markers (VB6 / .NET / packer entry thunks). These are
#: compiler-emitted, present in EVERY binary of that runtime, and carry zero
#: family signal -- but the goodware corpus is language-mismatched with the
#: malware (G_stats is 0.5% VB6 / 2.4% .NET, while families like guloader are
#: VB6 and njrat are .NET), so the DF index cannot see their genericity: it has
#: almost no VB6/.NET goodware to count them in. Without this list a VB6 family
#: marker like ``__vbaStrMove`` reads as "0 goodware -> promote" and matches
#: every VB6 program on earth (the pre-wipe FP catastrophe). This is the curated
#: patch; the complete fix is goodware augmentation (see NOTE.md R17). Entries
#: are matched on IMPORT candidates (import function/DLL names).
RUNTIME_IMPORTS = frozenset({
    # .NET entry thunks + framework core (universal to every managed binary).
    "mscoree.dll", "mscorlib", "mscorlib.dll", "mscoree",
    "_corexemain", "_cordllmain", "_corexemain@0", "_cordllmain@0",
    "system.private.corelib",
    # VB6 runtime library itself.
    "msvbvm60.dll", "msvbvm50.dll",
})

#: Regex markers for runtime thunks whose exact spelling varies. ``__vba*`` are
#: MSVBVM60 runtime intrinsics -- a VB6 program cannot define its own, so the
#: whole prefix is compiler boilerplate; ``_cor*main`` covers the .NET entry
#: stub variants.
RUNTIME_IMPORT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^__vba[a-z0-9_]+$"),
    re.compile(r"^_cor(exe|dll)main(@\d+)?$"),
)

#: .NET framework namespace roots that appear as strings in every managed
#: binary. Matched as substrings on text candidates. Kept to the runtime core:
#: broader ``system.*`` namespaces (e.g. sockets, crypto) carry family signal
#: and are deliberately NOT listed.
DOTNET_RUNTIME_SUBSTRINGS: tuple[str, ...] = (
    "mscorlib", "mscoree.dll", ".net framework",
    "system.runtime", "system.reflection", "system.private.corelib",
    "system.resources", "system.diagnostics",
)

#: P/Invoke marshalling signature fragments. These appear verbatim in the .NET
#: metadata of any managed binary that calls the corresponding Win32 API, so
#: they identify the *API being called*, not the family calling it. Kept narrow:
#: parameter-name fragments only, never the API names themselves (``CreateFile``
#: is family signal; ``lpVolumeNameBuffer`` is the compiler spelling out a
#: signature). Sourced from the 2026-08-20 njrat attribution survivors.
MARSHALLING_SUBSTRINGS: tuple[str, ...] = (
    "lpvolumenamebuffer", "nvolumenamesize", "lprootpathname",
    "nfilesystemnamesize", "lpfilesystemnamebuffer", "lpbuffer",
    "lpnumberofbyteswritten", "lpnumberofbytesread", "dwflagsandattributes",
    "lpsecurityattributes", "lpthreadattributes", "lpstartupinfo",
    "lpprocessinformation", "lpoverlapped", "lpfilesystemflags",
    "nfilesystemnamebuffer", "lpmaximumcomponentlength", "lpvolumeserialnumber",
)


def _decoded_text(hex_body: str) -> str:
    """ASCII rendering of a hex span, lowercased; "" if it is not text-bearing.

    NUL is treated as a separator, not a terminator: .NET and VB6 metadata pack
    length-prefixed strings back to back, so the interesting token is routinely
    on the far side of a 00.
    """
    try:
        raw = bytes.fromhex(hex_body.replace(" ", ""))
    except ValueError:
        return ""
    chars = [chr(b) if 32 <= b < 127 else " " for b in raw]
    text = "".join(chars).lower()
    return text if any(ch.isalpha() for ch in text) else ""


def _decoded_tokens(decoded: str) -> list[str]:
    return [t for t in decoded.split() if t]


#: One blob of every runtime/marshalling token we consider compiler-authored.
#: An attributed span is an arbitrary byte range, so it usually arrives cut
#: mid-token (``fer.nVolumeNa``): the needle is a fragment OF a known name, not
#: a text containing one. Matching therefore runs in both directions against
#: this blob.
_BOILERPLATE_BLOB = " ".join((
    *MARSHALLING_SUBSTRINGS,
    "readbyte", "writebyte", "tostring", "tolower", "toupper", "tolong",
    "getbytes", "computehash", "compareexchange", "memberwiseclone",
    "setprojectinformation", "clearprojecterror", "orobject", "objectequal",
    "cotaskmemfree", "cotaskmemalloc", "shell32.dll", "ole32.dll",
    "runtimetypehandle", "compilergenerated", "debuggerbrowsable",
))

#: Minimum decoded run length before a fragment may be matched against the blob.
#: 8 on purpose: at 6, ``system`` (from ``System.Net.Sockets``, real family
#: signal) is a substring of ``lpfilesystemnamebuffer`` and would be killed.
MIN_DECODED_FRAGMENT = 8


def _decoded_is_boilerplate(decoded: str) -> str | None:
    for run in _decoded_tokens(decoded):
        if len(run) < MIN_DECODED_FRAGMENT:
            continue
        if run in _BOILERPLATE_BLOB:
            return f"hex_decoded_runtime:{run[:24]}"
    return None


#: Minimum distinct byte values in a hex span. A run of identical bytes -- null
#: padding above all -- occurs in essentially every PE, so it is the hex analogue
#: of a generic section name: high prevalence, zero discriminative power, and
#: invisible to the goodware DF index (which indexes strings, not byte spans).
MIN_HEX_DISTINCT_BYTES = 3
#: Maximum share of a span that may be 0x00.
MAX_HEX_NULL_FRAC = 0.5

_SECTION_TYPES = frozenset({CType.PE_SECTION})
_DLL_TYPES = frozenset({CType.IMPORT})
_TEXTY_TYPES = frozenset({
    CType.STRING_ASCII, CType.STRING_WIDE, CType.YARA_STR, CType.PE_METADATA,
    CType.PE_ORIGINAL_FILENAME, CType.FILE_NAME, CType.FILE_PATH, CType.MUTEX,
})


def trivial_hex_reason(hex_body: str) -> str | None:
    """Reject byte spans with no discriminative content.

    Looks only at fixed bytes: wildcards and jumps carry no identity, so a span
    that is mostly ``??`` around two real bytes is not saved by its length.
    """
    fixed = [t for t in hex_body.split(" ")
             if len(t) == 2 and "?" not in t and not t.startswith("~")]
    if not fixed:
        return "trivial_hex_no_fixed_bytes"
    if len(set(fixed)) < MIN_HEX_DISTINCT_BYTES:
        return f"trivial_hex_distinct:{len(set(fixed))}"
    if sum(1 for t in fixed if t == "00") / len(fixed) > MAX_HEX_NULL_FRAC:
        return "trivial_hex_nulls"
    return None


@dataclass
class Stoplist:
    """Type-aware curated stoplist.

    ``hits`` returns the id of the rule that fired (for auditability in the
    dropped-candidate report), or ``None`` if the candidate is clean.
    """

    extra_exact: frozenset[str] = field(default_factory=frozenset)
    extra_substrings: tuple[str, ...] = ()
    #: Also apply the DLL list to text candidates that are bare DLL names.
    dll_names_as_strings: bool = True

    def hits(self, cand: Candidate) -> str | None:
        # Fold case here rather than relying on ``norm``: case-sensitive types
        # (STRING_ASCII) keep their case in ``norm``, but generic boilerplate is
        # generic in any casing.
        norm = cand.norm.lower()
        if not norm:
            return "empty"

        if norm in self.extra_exact:
            return "extra_exact"
        for sub in self.extra_substrings:
            if sub in norm:
                return f"extra_substring:{sub[:24]}"

        if cand.is_hex:
            trivial = trivial_hex_reason(cand.norm)
            if trivial:
                return trivial
            # A classifier-attributed span is an arbitrary byte range, so runtime
            # boilerplate reaches us as HEX_SPAN rather than as an IMPORT or a
            # string -- and would otherwise skip every rule below. Measured
            # 2026-08-20: 0 of 12 real attribution survivors were caught before
            # this decode. Only the printable part is checked; pure-opcode spans
            # legitimately fall through to the span DF index.
            decoded = _decoded_text(cand.norm)
            if decoded:
                for sub in BOILERPLATE_SUBSTRINGS:
                    if sub in decoded:
                        return f"hex_decoded_boilerplate:{sub[:24]}"
                for sub in DOTNET_RUNTIME_SUBSTRINGS:
                    if sub in decoded:
                        return f"hex_decoded_dotnet:{sub[:24]}"
                for pat in RUNTIME_IMPORT_PATTERNS:
                    if any(pat.match(tok) for tok in _decoded_tokens(decoded)):
                        return "hex_decoded_runtime_import"
                fragment = _decoded_is_boilerplate(decoded)
                if fragment:
                    return fragment
                # The Rich header is MSVC's build-provenance block: masked
                # compiler ids and object counts. Samples of one family share it
                # because they share a toolchain, not because they are related,
                # so it matches every binary from that compiler build.
                if "rich" in decoded:
                    return "hex_rich_header"
            return None

        if cand.ctype in _SECTION_TYPES:
            if norm in GENERIC_SECTIONS:
                return "generic_section"
            if norm in PACKER_SECTIONS:
                return "packer_section"
            return None

        if cand.ctype in _DLL_TYPES:
            if norm in SYSTEM_DLLS:
                return "system_dll"
            if norm in UNIVERSAL_IMPORTS:
                return "universal_import"
            if norm in RUNTIME_IMPORTS:
                return "runtime_import"
            for pat in SYSTEM_DLL_PATTERNS:
                if pat.match(norm):
                    return "system_dll_pattern"
            for pat in RUNTIME_IMPORT_PATTERNS:
                if pat.match(norm):
                    return "runtime_import_pattern"
            return None

        if cand.ctype in _TEXTY_TYPES:
            if self.dll_names_as_strings and norm.endswith(".dll"):
                if norm in SYSTEM_DLLS:
                    return "system_dll"
                if norm in RUNTIME_IMPORTS:
                    return "runtime_import"
                for pat in SYSTEM_DLL_PATTERNS:
                    if pat.match(norm):
                        return "system_dll_pattern"
            for sub in BOILERPLATE_SUBSTRINGS:
                if sub in norm:
                    return f"boilerplate:{sub[:24]}"
            for sub in DOTNET_RUNTIME_SUBSTRINGS:
                if sub in norm:
                    return f"dotnet_runtime:{sub[:24]}"
            # Marshalling signature fragments reach us as plain strings too, not
            # only inside attributed byte spans: the .NET metadata that names a
            # P/Invoke parameter is an extracted string in its own right.
            # `lpFileSystemFlags` survived into a BinaryToRule smoke rule
            # (2026-08-21) because this list was only consulted for hex.
            for sub in MARSHALLING_SUBSTRINGS:
                if sub in norm:
                    return f"marshalling:{sub[:24]}"
            return None

        return None

    def filter(
        self, cands: Iterable[Candidate]
    ) -> tuple[list[Candidate], dict[str, list[Candidate]]]:
        kept: list[Candidate] = []
        dropped: dict[str, list[Candidate]] = {}
        for c in cands:
            reason = self.hits(c)
            if reason is None:
                kept.append(c)
            else:
                dropped.setdefault(reason, []).append(c)
        return kept, dropped

    @classmethod
    def with_extras(
        cls, exact: Sequence[str] = (), substrings: Sequence[str] = ()
    ) -> "Stoplist":
        return cls(
            extra_exact=frozenset(s.lower() for s in exact),
            extra_substrings=tuple(s.lower() for s in substrings),
        )

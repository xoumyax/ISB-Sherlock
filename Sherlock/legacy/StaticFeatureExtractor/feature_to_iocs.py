"""
Bridge: StaticFeatures + FeatureAssessment → IOC dicts for iocs_to_prompt().

The canonical iocs_to_prompt() in Agent/agent/ioc_prompt.py accepts two
extra keyword params:
    feature_assessment      : dict  (FeatureAssessment.to_dict())
    feature_yara_conditions : list  (directly-usable YARA condition strings)

This module produces all three inputs from a StaticFeatures object so the
full pipeline can be triggered with one call.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .feature_model import FeatureAssessment
    from .schema import StaticFeatures


def features_to_ioc_dicts(
    features: "StaticFeatures",
    *,
    include_hashes: bool = False,
    max_sections: int = 8,
    max_strings: int = 30,
) -> list[dict[str, str]]:
    """
    Convert StaticFeatures → flat list of {label, text} IOC dicts.

    These are compatible with the iocs_to_prompt() pipeline (both the Agent
    and apps/chat versions).  The caller can pass the result directly as the
    `iocs` argument.

    Args:
        include_hashes: If True, include MD5/SHA-1/SHA-256 hashes.  Usually
                        False because hash-based YARA conditions identify a
                        single file and don't survive recompilation.
        max_sections:   Maximum number of sections to emit.
        max_strings:    Maximum number of URL/IP/registry/path strings.
    """
    iocs: list[dict[str, str]] = []

    # ── Hashes (opt-in) ───────────────────────────────────────────────────────
    if include_hashes:
        h = features.hashes
        if h.md5:
            iocs.append({"label": "md5", "text": h.md5})
        if h.sha1:
            iocs.append({"label": "sha-1", "text": h.sha1})
        if h.sha256:
            iocs.append({"label": "sha-256", "text": h.sha256})
        if h.ssdeep:
            iocs.append({"label": "ssdeep", "text": h.ssdeep})

    # ── File-type signals ─────────────────────────────────────────────────────
    ft = features.file_type
    if ft.libmagic:
        iocs.append({"label": "magic", "text": ft.libmagic})
    if ft.magika:
        iocs.append({"label": "magika", "text": ft.magika})

    # ── PE sections (name / size / entropy — skip common names) ──────────────
    _COMMON_SECTIONS = {
        ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
        ".idata", ".edata", ".pdata", ".tls", ".debug",
        ".crt", ".sxdata", ".xdata", ".gfids",
    }
    for sec in features.pe_sections[:max_sections]:
        name_lc = (sec.name or "").lower()
        if name_lc and name_lc not in _COMMON_SECTIONS:
            iocs.append({"label": "pe.section.name", "text": sec.name})
        if sec.raw_size and sec.raw_size >= 512:
            iocs.append({"label": "pe.section.size", "text": str(sec.raw_size)})
        if sec.entropy and sec.entropy >= 7.0:
            iocs.append({"label": "pe.section.entropy", "text": f"{sec.entropy:.2f}"})

    # ── PE resources ──────────────────────────────────────────────────────────
    for res in features.pe_resources[:4]:
        if res.type and res.name:
            iocs.append({"label": "pe.resources", "text": f"{res.type}/{res.name}"})

    # ── .NET features ─────────────────────────────────────────────────────────
    if features.dotnet:
        d = features.dotnet
        if d.assembly_name:
            iocs.append({"label": "dotnet.assembly_name", "text": d.assembly_name})
        if d.module_name:
            iocs.append({"label": "dotnet.name", "text": d.module_name})
        if d.version:
            iocs.append({"label": "dotnet.version", "text": d.version})
        for stream in d.streams[:4]:
            iocs.append({"label": "dotnet.stream", "text": stream})
        if d.typelib_id:
            iocs.append({"label": "pe.typelib", "text": d.typelib_id})

    # ── Strings: URLs, IPs, registry keys, paths, emails ─────────────────────
    strings = features.strings
    if strings:
        for url in strings.urls[:max_strings]:
            iocs.append({"label": "url", "text": url})
            host = _url_host(url)
            if host and "." in host:
                iocs.append({"label": "domain", "text": host})

        for ip in strings.ips[:max_strings]:
            iocs.append({"label": "ip", "text": ip})

        for key in strings.registry_keys[:max_strings]:
            iocs.append({"label": "registry", "text": key})

        for path in strings.paths[:max_strings]:
            iocs.append({"label": "file", "text": path})

        if hasattr(strings, "emails"):
            for email in strings.emails[:max_strings]:
                iocs.append({"label": "email", "text": email})

    return iocs


def features_to_prompt_kwargs(
    features: "StaticFeatures",
    assessment: "FeatureAssessment | None" = None,
    *,
    include_hashes: bool = False,
    max_sections: int = 8,
    max_strings: int = 30,
    malware_context: str | None = None,
) -> dict[str, Any]:
    """
    Produce the full kwargs dict for iocs_to_prompt().

    Usage::

        from StaticFeatureExtractor.feature_to_iocs import features_to_prompt_kwargs
        from Agent.agent.ioc_prompt import iocs_to_prompt

        kwargs = features_to_prompt_kwargs(features, assessment)
        result = iocs_to_prompt(**kwargs)

    Returns a dict with keys:
        iocs                    : list[dict]    → pass as positional iocs arg
        feature_assessment      : dict | None
        feature_yara_conditions : list[str]
        malware_context         : str | None
    """
    iocs = features_to_ioc_dicts(
        features,
        include_hashes=include_hashes,
        max_sections=max_sections,
        max_strings=max_strings,
    )

    feature_assessment_dict: dict[str, Any] | None = None
    feature_yara_conditions: list[str] = []

    if assessment is not None:
        feature_assessment_dict = assessment.to_dict()
        feature_yara_conditions = assessment.selected_yara_conditions()

    # Fallback: pull structural conditions from the features object itself
    if not feature_yara_conditions:
        feature_yara_conditions = features.to_yara_conditions()

    return {
        "iocs": iocs,
        "feature_assessment": feature_assessment_dict,
        "feature_yara_conditions": feature_yara_conditions,
        "malware_context": malware_context,
    }


def _url_host(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.hostname or ""
    except Exception:
        return ""

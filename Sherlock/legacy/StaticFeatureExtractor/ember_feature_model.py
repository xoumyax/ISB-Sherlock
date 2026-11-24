"""
EmberFeatureModel — EMBER2024-backed malware detector + YARA condition selector.

Pipeline per file:
  1. PEFeatureExtractor (thrember)  → 2568-dim feature vector
  2. LightGBM binary classifier     → malware probability + verdict
  3. SHAP TreeExplainer             → per-sample feature importance
  4. Feature-group mapper           → FeatureSignal list with YARA conditions

The SHAP step is what makes this different from global feature importance:
it tells us exactly which feature groups drove THIS sample's detection,
so the generated YARA conditions are sample-specific, not generic.

Requires: thrember, lightgbm, shap (all optional — graceful fallback)
EMBER2024 project root must be on sys.path or installed.
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from .schema import StaticFeatures

from .feature_model import FeatureAssessment, FeatureModel, FeatureSignal

logger = logging.getLogger(__name__)

# ── EMBER2024 feature-group layout ────────────────────────────────────────────
# Each entry: (group_name, start_dim, end_dim_exclusive)
# Computed from PEFeatureExtractor dim values in thrember/features.py

_GROUPS: list[tuple[str, int, int]] = [
    ("general",          0,    7),
    ("histogram",        7,    263),
    ("byteentropy",      263,  519),
    ("strings",          519,  696),
    ("section",          696,  920),
    ("imports",          920,  2202),
    ("exports",          2202, 2331),
    ("header",           2331, 2405),
    ("datadirectories",  2405, 2439),
    ("richheader",       2439, 2472),
    ("authenticode",     2472, 2480),
    ("pefilewarnings",   2480, 2568),
]

# Within "general" group, offset → semantic name
_GENERAL_OFFSETS: dict[int, str] = {
    0: "size", 1: "entropy", 2: "is_pe",
    3: "start_byte_0", 4: "start_byte_1", 5: "start_byte_2", 6: "start_byte_3",
}

# Within "strings" group, offset → semantic name (first 5 scalar features)
_STRINGS_OFFSETS: dict[int, str] = {
    0: "numstrings", 1: "avlength", 2: "printable_ratio",
    3: "urls_count", 4: "paths_count",
}

# Within "header" group, key offsets (machine type at 0)
_HEADER_OFFSETS: dict[int, str] = {0: "machine_type", 1: "subsystem"}

# Authenticode offsets
_AUTH_OFFSETS: dict[int, str] = {0: "has_valid_signature", 1: "cert_count"}


def _dim_to_group(dim: int) -> tuple[str, int]:
    """Return (group_name, offset_within_group) for absolute feature dimension."""
    for name, start, end in _GROUPS:
        if start <= dim < end:
            return name, dim - start
    return "unknown", dim


# ── YARA condition templates ───────────────────────────────────────────────────
# Maps (group_name, sub_key) → (signal_name, description, yara_condition)
# sub_key is either an offset tag or a semantic label for that group.

_YARA_MAP: dict[tuple[str, str], tuple[str, str, str]] = {
    # General file properties
    ("general", "entropy_high"):
        ("file_entropy_high",
         "Overall file entropy > 7.2 — common for packed/encrypted payloads",
         "math.entropy(0, filesize) > 7.2"),
    ("general", "not_pe"):
        ("not_pe_magic",
         "File does not start with MZ magic — may be shellcode or packed blob",
         "not uint16(0) == 0x5a4d"),

    # Strings
    ("strings", "urls"):
        ("embedded_urls",
         "File contains embedded HTTP/HTTPS URLs — common in downloaders/C2",
         'pe.number_of_resources > 0 and for any s in pe.resources : ( s.length > 4 )'),
    ("strings", "paths"):
        ("embedded_paths",
         "File contains embedded filesystem paths",
         "for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].raw_size > 512 )"),
    ("strings", "many_strings"):
        ("high_string_count",
         "File contains an unusually high number of printable strings",
         None),  # no direct YARA condition — informational

    # Sections
    ("section", "entropy_high"):
        ("section_entropy_high",
         "One or more PE sections have entropy > 7.0 — packed/encrypted section",
         "for any i in (0..pe.number_of_sections-1) : ( math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.0 )"),
    ("section", "few_sections"):
        ("few_sections",
         "PE has fewer than 3 sections — unusual for legitimate executables",
         "pe.number_of_sections < 3"),
    ("section", "many_sections"):
        ("many_sections",
         "PE has an unusually large number of sections",
         "pe.number_of_sections > 8"),
    ("section", "empty_names"):
        ("blank_section_names",
         "One or more sections have blank/empty names — common in packers",
         'for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].name == "" )'),

    # Imports
    ("imports", "few_imports"):
        ("few_imports",
         "PE imports very few functions — typical after packing or manual IAT",
         "pe.number_of_imported_symbols < 5"),
    ("imports", "suspicious_apis"):
        ("memory_alloc_imports",
         "PE imports memory allocation / code injection APIs",
         'pe.imports("kernel32.dll", "VirtualAlloc") or pe.imports("kernel32.dll", "VirtualAllocEx")'),
    ("imports", "remote_thread"):
        ("remote_thread_imports",
         "PE imports remote thread creation APIs — indicator of process injection",
         'pe.imports("kernel32.dll", "CreateRemoteThread") or pe.imports("kernel32.dll", "CreateRemoteThreadEx")'),
    ("imports", "write_process"):
        ("write_process_memory_imports",
         "PE imports WriteProcessMemory — process injection indicator",
         'pe.imports("kernel32.dll", "WriteProcessMemory")'),
    ("imports", "load_library"):
        ("load_library_imports",
         "PE imports LoadLibrary — dynamic loading, common in loaders",
         'pe.imports("kernel32.dll", "LoadLibraryA") or pe.imports("kernel32.dll", "LoadLibraryW")'),
    ("imports", "registry_apis"):
        ("registry_apis",
         "PE imports registry manipulation APIs — persistence / config storage",
         'pe.imports("advapi32.dll", "RegSetValueExA") or pe.imports("advapi32.dll", "RegCreateKeyExA")'),
    ("imports", "network_apis"):
        ("network_apis",
         "PE imports Winsock / WinHTTP networking APIs — C2 or download",
         'pe.imports("ws2_32.dll") or pe.imports("winhttp.dll") or pe.imports("wininet.dll")'),
    ("imports", "crypto_apis"):
        ("crypto_apis",
         "PE imports Windows CryptoAPI — encryption, ransomware indicator",
         'pe.imports("advapi32.dll", "CryptEncrypt") or pe.imports("crypt32.dll")'),

    # Exports
    ("exports", "has_exports"):
        ("has_exports",
         "PE file has exported functions — may be DLL payload",
         "pe.number_of_exports > 0"),

    # Header
    ("header", "no_debug"):
        ("no_debug_info",
         "PE has no debug directory — stripped binary, common in malware",
         "not pe.is_dll and pe.number_of_sections > 0 and not pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_DEBUG].size > 0"),
    ("header", "dll"):
        ("is_dll",
         "File is a DLL — may be injected payload or side-loaded module",
         "pe.characteristics & pe.DLL"),
    ("header", "x64"):
        ("x64_binary",
         "64-bit PE binary",
         "pe.machine == pe.MACHINE_AMD64"),
    ("header", "x86"):
        ("x86_binary",
         "32-bit x86 PE binary",
         "pe.machine == pe.MACHINE_I386"),

    # Authenticode
    ("authenticode", "unsigned"):
        ("unsigned_binary",
         "PE has no Authenticode signature — common in untrusted/malicious files",
         "not pe.is_signed"),
    ("authenticode", "invalid_sig"):
        ("invalid_signature",
         "PE has a signature that fails validation",
         "pe.is_signed and not pe.signatures[0].valid_on(pe.CERT_DATE_ANY)"),

    # Rich header
    ("richheader", "no_rich"):
        ("no_rich_header",
         "PE has no Rich header — manually crafted or tool-produced binary",
         "pe.rich_signature.length == 0"),

    # Byte entropy
    ("byteentropy", "bimodal"):
        ("bimodal_entropy",
         "Byte entropy distribution suggests mixed plaintext+encrypted content",
         None),

    # Data directories
    ("datadirectories", "no_tls"):
        ("no_tls_directory",
         "PE has no TLS directory",
         "pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_TLS].size == 0"),
    ("datadirectories", "has_tls"):
        ("has_tls_directory",
         "PE has a TLS directory — can be used for anti-analysis callbacks",
         "pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_TLS].size > 0"),
}


def _shap_to_signals(
    shap_values: "np.ndarray",
    feature_vector: "np.ndarray",
    top_k: int = 12,
) -> list[FeatureSignal]:
    """
    Convert per-sample SHAP values to a ranked list of FeatureSignals.

    Strategy:
      1. Rank feature dimensions by |SHAP value| descending.
      2. Aggregate by group — take the max |SHAP| within each group.
      3. For the top groups, emit specific signals based on the feature values
         in that group (e.g. high entropy → entropy signal; few imports → few_imports signal).
    """
    abs_shap = np.abs(shap_values)

    # Aggregate to groups
    group_importance: dict[str, float] = {}
    group_feature_values: dict[str, np.ndarray] = {}
    for name, start, end in _GROUPS:
        group_shap = abs_shap[start:end]
        group_importance[name] = float(group_shap.max()) if len(group_shap) else 0.0
        group_feature_values[name] = feature_vector[start:end]

    ranked_groups = sorted(group_importance, key=group_importance.get, reverse=True)  # type: ignore[arg-type]

    signals: list[FeatureSignal] = []
    seen_keys: set[tuple[str, str]] = set()

    def _add(group: str, sub_key: str, importance: float) -> None:
        key = (group, sub_key)
        if key in seen_keys:
            return
        seen_keys.add(key)
        entry = _YARA_MAP.get(key)
        if entry is None:
            return
        name, description, yara_condition = entry
        signals.append(FeatureSignal(
            name=name,
            category=group,
            value=importance,
            weight=round(importance, 4),
            confidence=1.0,
            reason=description,
            yara_condition=yara_condition,
        ))

    for group in ranked_groups[:8]:
        imp = group_importance[group]
        vals = group_feature_values.get(group, np.array([]))

        if group == "general":
            entropy_val = float(vals[1]) if len(vals) > 1 else 0.0
            if entropy_val > 7.2:
                _add(group, "entropy_high", imp)
            is_pe = bool(vals[2]) if len(vals) > 2 else True
            if not is_pe:
                _add(group, "not_pe", imp)

        elif group == "strings":
            url_count = float(vals[3]) if len(vals) > 3 else 0.0
            path_count = float(vals[4]) if len(vals) > 4 else 0.0
            str_count = float(vals[0]) if len(vals) > 0 else 0.0
            if url_count > 0:
                _add(group, "urls", imp)
            if path_count > 0:
                _add(group, "paths", imp)
            if str_count > 2000:
                _add(group, "many_strings", imp)

        elif group == "section":
            # section group: first 11 dims are scalar section stats
            # dims 0-2: n_sections, n_rx, n_r; dim 5: avg_entropy
            n_sections = float(vals[0]) if len(vals) > 0 else 0.0
            avg_entropy = float(vals[5]) if len(vals) > 5 else 0.0
            n_empty_names = float(vals[3]) if len(vals) > 3 else 0.0
            if avg_entropy > 7.0:
                _add(group, "entropy_high", imp)
            if n_sections < 3:
                _add(group, "few_sections", imp)
            if n_sections > 8:
                _add(group, "many_sections", imp)
            if n_empty_names > 0:
                _add(group, "empty_names", imp)

        elif group == "imports":
            # First 2 dims: n_imports, n_dlls (from ImportsInfo)
            n_imports = float(vals[0]) if len(vals) > 0 else 0.0
            if n_imports < 5:
                _add(group, "few_imports", imp)
            else:
                # Always flag suspicious APIs when imports group is important
                _add(group, "suspicious_apis", imp)
                _add(group, "remote_thread", imp)
                _add(group, "network_apis", imp)

        elif group == "exports":
            n_exports = float(vals[0]) if len(vals) > 0 else 0.0
            if n_exports > 0:
                _add(group, "has_exports", imp)

        elif group == "header":
            # dim 0 = machine type (0x14c = x86, 0x8664 = x64)
            machine = float(vals[0]) if len(vals) > 0 else 0.0
            if machine == 0x14c:
                _add(group, "x86", imp)
            elif machine == 0x8664:
                _add(group, "x64", imp)
            # Check for DLL characteristic (bit 13 of characteristics)
            # This is in a later header dim — add generic signal
            _add(group, "no_debug", imp)

        elif group == "authenticode":
            has_sig = float(vals[0]) if len(vals) > 0 else 1.0
            if has_sig == 0:
                _add(group, "unsigned", imp)
            else:
                _add(group, "invalid_sig", imp)

        elif group == "richheader":
            rich_len = float(vals[0]) if len(vals) > 0 else 1.0
            if rich_len == 0:
                _add(group, "no_rich", imp)

        elif group == "datadirectories":
            # dim 20 = TLS directory size (entry 9 × 2 = offset 18, size at 19)
            tls_size = float(vals[19]) if len(vals) > 19 else 0.0
            if tls_size > 0:
                _add(group, "has_tls", imp)
            else:
                _add(group, "no_tls", imp)

        elif group == "byteentropy":
            _add(group, "bimodal", imp)

    signals.sort(key=lambda s: s.weight, reverse=True)
    return signals[:top_k]


# ── EmberFeatureModel ─────────────────────────────────────────────────────────

class EmberFeatureModel(FeatureModel):
    """
    EMBER2024-backed malware detector + YARA condition selector.

    Args:
        model_path:   Path to a trained LightGBM .model file (EMBER2024 binary classifier).
        threshold:    Probability above which a file is classified as malware_like.
        top_k:        Maximum number of YARA condition signals to return.
        use_shap:     If True, use SHAP TreeExplainer for per-sample explanation.
                      If False, uses global feature importance (faster, less precise).
        file_type:    thrember file type hint ("PE", "ELF", "APK", "PDF", etc.)
    """

    name = "ember_feature_model_v1"

    def __init__(
        self,
        model_path: str | Path,
        *,
        threshold: float = 0.50,
        top_k: int = 12,
        use_shap: bool = True,
        file_type: str = "PE",
    ) -> None:
        self.model_path = Path(model_path)
        self.threshold = threshold
        self.top_k = top_k
        self.use_shap = use_shap
        self.file_type = file_type
        self._model = None
        self._extractor = None
        self._explainer = None

    def _load(self) -> None:
        if self._model is not None:
            return
        try:
            import lightgbm as lgb
            self._model = lgb.Booster(model_file=str(self.model_path))
        except ImportError as exc:
            raise ImportError("lightgbm is required for EmberFeatureModel") from exc

        # Add EMBER2024 to sys.path if needed
        ember_src = Path(__file__).resolve().parents[1] / "EMBER2024" / "src"
        if ember_src.exists() and str(ember_src) not in sys.path:
            sys.path.insert(0, str(ember_src))

        try:
            from thrember import PEFeatureExtractor
            self._extractor = PEFeatureExtractor()
        except ImportError as exc:
            raise ImportError(
                "thrember is required for EmberFeatureModel. "
                "Install from EMBER2024/: pip install ."
            ) from exc

        if self.use_shap:
            try:
                import shap
                self._explainer = shap.TreeExplainer(self._model)
            except ImportError:
                logger.warning(
                    "shap not installed — falling back to global feature importance. "
                    "Install with: pip install shap"
                )
                self.use_shap = False
                self._shap_unavailable_reason = "shap library not installed"

    def assess(self, features: "StaticFeatures") -> FeatureAssessment:
        """Run EMBER detection and SHAP-guided YARA condition selection."""
        self._load()

        # Read raw bytes from the file path stored in StaticFeatures
        try:
            data = Path(features.path).read_bytes()
        except (OSError, AttributeError) as exc:
            return FeatureAssessment(
                is_likely_malware=False,
                probability=0.0,
                threshold=self.threshold,
                selected_features=[],
                supporting_signals=[],
                weak_or_contextual_signals=[],
                verdict="unknown",
                model_name=self.name,
                rationale=[f"Could not read file bytes: {exc}"],
            )

        # Extract EMBER feature vector
        try:
            vec = self._extractor.feature_vector(data).reshape(1, -1)
        except Exception as exc:
            return FeatureAssessment(
                is_likely_malware=False,
                probability=0.0,
                threshold=self.threshold,
                selected_features=[],
                supporting_signals=[],
                weak_or_contextual_signals=[],
                verdict="unknown",
                model_name=self.name,
                rationale=[f"EMBER feature extraction failed: {exc}"],
            )

        # Predict malware probability
        try:
            prob = float(self._model.predict(vec)[0])
        except Exception as exc:
            return FeatureAssessment(
                is_likely_malware=False,
                probability=0.0,
                threshold=self.threshold,
                selected_features=[],
                supporting_signals=[],
                weak_or_contextual_signals=[],
                verdict="unknown",
                model_name=self.name,
                rationale=[f"LightGBM prediction failed: {exc}"],
            )

        verdict = "malware_like" if prob >= self.threshold else "benign_like"

        # Generate YARA-relevant signals from SHAP or global importance
        signals: list[FeatureSignal] = []
        rationale: list[str] = []

        if self.use_shap and self._explainer is not None:
            try:
                shap_vals = self._explainer.shap_values(vec)[0]
                signals = _shap_to_signals(shap_vals, vec[0], top_k=self.top_k)
                rationale.append(
                    f"SHAP TreeExplainer identified top contributing feature groups "
                    f"from {len(shap_vals)} EMBER dims."
                )
            except Exception as exc:
                logger.warning("SHAP explanation failed: %s — using global importance", exc)
                signals = self._global_importance_signals()
                rationale.append(f"SHAP failed ({exc}); used global feature importance.")
        else:
            signals = self._global_importance_signals()
            reason = getattr(self, "_shap_unavailable_reason", None)
            suffix = f" ({reason})" if reason else ""
            rationale.append(
                f"Used global LGBM feature importance (use_shap=False){suffix} — "
                "explanations are model-wide, not per-sample."
            )

        rationale.append(
            f"EMBER2024 LightGBM: probability={prob:.4f}, threshold={self.threshold}, "
            f"verdict={verdict}."
        )

        return FeatureAssessment(
            is_likely_malware=(prob >= self.threshold),
            probability=round(prob, 4),
            threshold=self.threshold,
            selected_features=signals,
            supporting_signals=[],
            weak_or_contextual_signals=[],
            verdict=verdict,
            model_name=self.name,
            rationale=rationale,
        )

    def _global_importance_signals(self) -> list[FeatureSignal]:
        """Fallback: use LGBM global gain-based importance instead of SHAP."""
        importance = self._model.feature_importance(importance_type="gain")
        # Map top-k dims to signals with uniform group treatment
        top_dims = np.argsort(importance)[::-1][:64]
        group_seen: set[str] = set()
        signals: list[FeatureSignal] = []
        for dim in top_dims:
            group, _ = _dim_to_group(int(dim))
            if group in group_seen:
                continue
            group_seen.add(group)
            imp = float(importance[dim])
            # Emit the default signal for each group
            default_sub: dict[str, str] = {
                "imports": "suspicious_apis",
                "section": "entropy_high",
                "strings": "urls",
                "general": "entropy_high",
                "authenticode": "unsigned",
                "header": "no_debug",
                "exports": "has_exports",
                "richheader": "no_rich",
                "datadirectories": "has_tls",
            }
            sub = default_sub.get(group)
            if sub:
                entry = _YARA_MAP.get((group, sub))
                if entry:
                    name, description, yara_condition = entry
                    signals.append(FeatureSignal(
                        name=name,
                        category=group,
                        value=imp,
                        weight=round(imp, 4),
                        confidence=1.0,
                        reason=description,
                        yara_condition=yara_condition,
                    ))
            if len(signals) >= self.top_k:
                break
        return signals

    @classmethod
    def load(cls, model_path: str | Path, **kwargs: Any) -> "EmberFeatureModel":
        return cls(model_path, **kwargs)

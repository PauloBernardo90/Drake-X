"""Detection-engineering outputs for DEX deep analysis — YARA and STIX candidates.

Generates candidate YARA rules and STIX 2.1 bundles from DEX analysis
findings. Follows the same doctrine as the PE detection writer:

- Every rule is labeled **candidate — analyst review required**
- YARA candidates require at least two corroborating conditions
- STIX bundles contain only fact-level observables
- Timestamps are frozen for reproducibility
- Strings and patterns are taken verbatim from deterministic evidence

YARA rule types generated:
- Sensitive API combination rules (e.g., AccessibilityService + SmsManager)
- String IoC rules (URLs, C2 paths, shell commands found in DEX)
- Obfuscated loader rules (DexClassLoader + encoded strings)
- Package target overlay rules (target banking apps + WebView)
"""

from __future__ import annotations

import json
import uuid
from typing import Any, TYPE_CHECKING

from .. import __version__ as _drake_x_version

if TYPE_CHECKING:
    from ..models.dex import DexAnalysisResult

_STIX_TIMESTAMP_SENTINEL = "1970-01-01T00:00:00+00:00"
_YARA_GENERATED_AT_SENTINEL = "1970-01-01"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_dex_yara_candidates(
    result: DexAnalysisResult,
    *,
    sha256: str = "",
) -> str:
    """Render candidate YARA rules from DEX deep analysis findings.

    Returns empty string when no signals are strong enough.
    """
    rules: list[str] = []
    short = (sha256 or "unknown")[:16]

    rules.extend(_sensitive_api_rules(result, short, sha256))
    rules.extend(_string_ioc_rules(result, short, sha256))
    rules.extend(_obfuscated_loader_rules(result, short, sha256))
    rules.extend(_overlay_target_rules(result, short, sha256))

    if not rules:
        return ""

    header = _render_yara_header()
    return header + "\n\n".join(rules) + "\n"


def render_dex_stix_bundle(
    result: DexAnalysisResult,
    *,
    sha256: str = "",
    md5: str = "",
    file_size: int = 0,
) -> str:
    """Render a STIX 2.1 bundle from DEX findings.

    Returns empty string if no sha256 is provided.
    """
    if not sha256:
        return ""

    ts = _STIX_TIMESTAMP_SENTINEL
    bundle_id = f"bundle--{_stable_uuid('dex-bundle', sha256)}"

    file_obj: dict[str, Any] = {
        "type": "file",
        "spec_version": "2.1",
        "id": f"file--{_uuid_from_sha(sha256)}",
        "hashes": {"SHA-256": sha256},
        "size": file_size,
    }
    if md5:
        file_obj["hashes"]["MD5"] = md5

    objects: list[dict[str, Any]] = [file_obj]

    # Sensitive API hits as indicators
    seen_apis: set[str] = set()
    for i, hit in enumerate(result.sensitive_api_hits):
        key = f"{hit.api_category.value}:{hit.api_name}"
        if key in seen_apis or hit.confidence < 0.6:
            continue
        seen_apis.add(key)

        ind_key = f"{sha256}|dex_api|{i}|{hit.api_name}"
        indicator_id = f"indicator--{_stable_uuid('dex-indicator', ind_key)}"

        attck_refs = [
            {"source_name": "mitre-attack", "external_id": tid}
            for tid in hit.mitre_attck
        ]

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": ts,
            "modified": ts,
            "name": f"Drake-X DEX candidate: {hit.api_category.value} — {hit.api_name}",
            "description": (
                f"Sensitive API usage detected in DEX: {hit.api_name} "
                f"(category: {hit.api_category.value}). "
                "NOTE: candidate indicator — analyst review required."
            ),
            "indicator_types": ["anomalous-activity"],
            "labels": ["candidate", "drake-x-generated", "dex-analysis"],
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
            "valid_from": ts,
            "confidence": int(hit.confidence * 100),
            "external_references": attck_refs,
        })

        rel_key = f"{indicator_id}|{file_obj['id']}|indicates"
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{_stable_uuid('dex-rel', rel_key)}",
            "created": ts,
            "modified": ts,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": file_obj["id"],
        })

    # String IoCs as indicators
    iocs = [s for s in result.classified_strings if s.is_potential_ioc and s.confidence >= 0.7]
    for i, cs in enumerate(iocs[:20]):
        ind_key = f"{sha256}|dex_string|{i}|{cs.value[:50]}"
        indicator_id = f"indicator--{_stable_uuid('dex-string-ind', ind_key)}"

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": ts,
            "modified": ts,
            "name": f"Drake-X DEX string IoC: {cs.category.value}",
            "description": (
                f"String classified as {cs.category.value}: {cs.value[:100]}. "
                "NOTE: candidate — analyst review required."
            ),
            "indicator_types": ["malicious-activity"],
            "labels": ["candidate", "drake-x-generated", "dex-string-ioc"],
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
            "valid_from": ts,
            "confidence": int(cs.confidence * 100),
        })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
        "x_drake_x": {
            "generator_version": _drake_x_version,
            "generated_at": ts,
            "analysis_type": "dex_deep",
            "caveat": (
                "All indicators in this bundle are candidate outputs from "
                "Drake-X DEX deep analysis. They require analyst review and "
                "dynamic validation before operational use."
            ),
            "reproducibility_note": (
                "Timestamps are frozen to a sentinel for byte-reproducibility."
            ),
        },
    }
    return json.dumps(bundle, indent=2, default=str)


# ---------------------------------------------------------------------------
# YARA rule generators
# ---------------------------------------------------------------------------


def _sensitive_api_rules(
    result: DexAnalysisResult, short: str, sha: str,
) -> list[str]:
    """Generate YARA rules from sensitive API combinations."""
    high_apis = [
        h for h in result.sensitive_api_hits
        if h.confidence >= 0.7 and h.severity.value in ("high", "critical")
    ]
    if len(high_apis) < 2:
        return []

    # Deduplicate API names
    api_names = sorted({h.api_name for h in high_apis})
    if len(api_names) < 2:
        return []

    categories = sorted({h.api_category.value for h in high_apis})
    string_block = "\n".join(
        f'        $api_{i} = "{name}" ascii'
        for i, name in enumerate(api_names[:8])
    )

    return [
        f"rule Drake_Candidate_DexSensitiveAPIs_{short}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        analysis = "dex_deep"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        categories = "{", ".join(categories[:5])}"\n'
        f'        generated_at = "{_YARA_GENERATED_AT_SENTINEL}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"{string_block}\n"
        f"    condition:\n"
        f"        2 of ($api_*) and filesize < 50MB\n"
        f"}}"
    ]


def _string_ioc_rules(
    result: DexAnalysisResult, short: str, sha: str,
) -> list[str]:
    """Generate YARA rules from classified string IoCs."""
    iocs = [
        s for s in result.classified_strings
        if s.is_potential_ioc and s.confidence >= 0.7
        and s.category.value in ("url", "c2_indicator", "command")
        and len(s.value) >= 8
    ]
    if len(iocs) < 2:
        return []

    # Take up to 6 strongest IoC strings
    selected = sorted(iocs, key=lambda s: s.confidence, reverse=True)[:6]
    string_block = "\n".join(
        f'        $ioc_{i} = "{_escape_yara(s.value[:80])}" ascii'
        for i, s in enumerate(selected)
    )

    return [
        f"rule Drake_Candidate_DexStringIOCs_{short}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        analysis = "dex_deep"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        generated_at = "{_YARA_GENERATED_AT_SENTINEL}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"{string_block}\n"
        f"    condition:\n"
        f"        2 of ($ioc_*) and filesize < 50MB\n"
        f"}}"
    ]


def _obfuscated_loader_rules(
    result: DexAnalysisResult, short: str, sha: str,
) -> list[str]:
    """Generate YARA rule for obfuscated dynamic loader pattern."""
    has_loader = any(
        h.api_category.value == "dex_loading" and h.confidence >= 0.7
        for h in result.sensitive_api_hits
    )
    has_obfuscation = result.obfuscation_score >= 0.4

    if not (has_loader and has_obfuscation):
        return []

    # Build rule combining loader string + obfuscation signals
    strings: list[str] = [
        '        $loader1 = "DexClassLoader" ascii',
        '        $loader2 = "InMemoryDexClassLoader" ascii',
        '        $loader3 = "PathClassLoader" ascii',
        '        $loader4 = "loadClass" ascii',
    ]

    # Add reflection strings if detected
    has_reflection = any(
        h.api_category.value == "reflection" and h.confidence >= 0.5
        for h in result.sensitive_api_hits
    )
    if has_reflection:
        strings.append('        $refl1 = "Class.forName" ascii')
        strings.append('        $refl2 = "getDeclaredMethod" ascii')

    string_block = "\n".join(strings)

    return [
        f"rule Drake_Candidate_DexObfuscatedLoader_{short}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        analysis = "dex_deep"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        obfuscation_score = "{result.obfuscation_score:.2f}"\n'
        f'        generated_at = "{_YARA_GENERATED_AT_SENTINEL}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"{string_block}\n"
        f"    condition:\n"
        f"        2 of ($loader*) and filesize < 50MB\n"
        f"}}"
    ]


def _overlay_target_rules(
    result: DexAnalysisResult, short: str, sha: str,
) -> list[str]:
    """Generate YARA rule for overlay/phishing target pattern."""
    has_webview = any(
        h.api_category.value == "webview" and h.confidence >= 0.5
        for h in result.sensitive_api_hits
    )
    has_accessibility = any(
        h.api_category.value == "accessibility_service"
        for h in result.sensitive_api_hits
    )
    target_packages = [
        s for s in result.classified_strings
        if s.category.value == "package_target" and s.confidence >= 0.6
    ]

    if not ((has_webview or has_accessibility) and len(target_packages) >= 2):
        return []

    strings: list[str] = []
    if has_accessibility:
        strings.append('        $a11y = "AccessibilityService" ascii')
    if has_webview:
        strings.append('        $webview = "WebView" ascii')

    for i, pkg in enumerate(target_packages[:5]):
        strings.append(f'        $target_{i} = "{_escape_yara(pkg.value)}" ascii')

    string_block = "\n".join(strings)

    needed = 2 if has_accessibility else 3

    return [
        f"rule Drake_Candidate_DexOverlayTargets_{short}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        analysis = "dex_deep"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        generated_at = "{_YARA_GENERATED_AT_SENTINEL}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"{string_block}\n"
        f"    condition:\n"
        f"        {needed} of them and filesize < 50MB\n"
        f"}}"
    ]


# ---------------------------------------------------------------------------
# VT enrichment correlation
# ---------------------------------------------------------------------------


def correlate_dex_with_vt(
    result: DexAnalysisResult,
    vt_data: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Cross-reference DEX findings with VirusTotal enrichment data.

    Returns a list of correlation observations where DEX-detected behaviors
    align with (or contradict) VT classifications.
    """
    if not vt_data:
        return []

    correlations: list[dict[str, Any]] = []

    vt_tags = set(vt_data.get("tags", []))
    vt_label = (vt_data.get("popular_threat_label", "") or "").lower()
    vt_suggested = (vt_data.get("suggested_threat_label", "") or "").lower()
    vt_detections = vt_data.get("detections", 0)

    # Correlation 1: VT detects as banker/trojan + DEX finds banking targets
    banking_strings = [
        s for s in result.classified_strings
        if s.category.value == "package_target" and "bank" in s.value.lower()
    ]
    if banking_strings and any(kw in vt_label for kw in ("banker", "trojan", "spy")):
        correlations.append({
            "type": "vt_confirms_dex",
            "description": (
                f"VT label '{vt_label}' corroborates DEX finding of "
                f"{len(banking_strings)} banking package target(s)"
            ),
            "dex_evidence": [s.value for s in banking_strings[:3]],
            "vt_evidence": vt_label,
            "confidence": 0.85,
        })

    # Correlation 2: VT detects as dropper + DEX finds DexClassLoader
    has_loader = any(
        h.api_category.value == "dex_loading" for h in result.sensitive_api_hits
    )
    if has_loader and any(kw in vt_label for kw in ("dropper", "loader")):
        correlations.append({
            "type": "vt_confirms_dex",
            "description": (
                f"VT label '{vt_label}' corroborates DEX finding of dynamic class loading"
            ),
            "dex_evidence": ["DexClassLoader / dynamic loading detected"],
            "vt_evidence": vt_label,
            "confidence": 0.8,
        })

    # Correlation 3: VT detects SMS abuse + DEX finds SmsManager
    has_sms = any(
        h.api_category.value == "sms" for h in result.sensitive_api_hits
    )
    if has_sms and any(kw in vt_label for kw in ("sms", "smssend", "smspay")):
        correlations.append({
            "type": "vt_confirms_dex",
            "description": "VT classification aligns with DEX-detected SMS API usage",
            "dex_evidence": ["SmsManager usage detected"],
            "vt_evidence": vt_label,
            "confidence": 0.85,
        })

    # Correlation 4: High VT detection + high DEX obfuscation score
    if vt_detections > 20 and result.obfuscation_score >= 0.5:
        correlations.append({
            "type": "vt_supports_dex",
            "description": (
                f"High VT detection ratio ({vt_detections} engines) correlates with "
                f"high DEX obfuscation score ({result.obfuscation_score:.0%})"
            ),
            "dex_evidence": [f"Obfuscation score: {result.obfuscation_score:.2f}"],
            "vt_evidence": f"{vt_detections} detections",
            "confidence": 0.7,
        })

    # Correlation 5: DEX finds sensitive APIs but VT shows 0 detections
    high_risk_apis = [
        h for h in result.sensitive_api_hits
        if h.severity.value in ("high", "critical") and h.confidence >= 0.7
    ]
    if high_risk_apis and vt_detections == 0:
        correlations.append({
            "type": "dex_contradicts_vt",
            "description": (
                f"DEX found {len(high_risk_apis)} high-risk API(s) but VT shows "
                "0 detections — possible zero-day, FP, or newly submitted sample"
            ),
            "dex_evidence": [h.api_name for h in high_risk_apis[:5]],
            "vt_evidence": "0 detections",
            "confidence": 0.5,
        })

    return correlations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _render_yara_header() -> str:
    return (
        "/*\n"
        " * Drake-X CANDIDATE YARA rules (DEX deep analysis).\n"
        " *\n"
        " * These rules are generated from DEX disassembly evidence and are\n"
        " * NOT VALIDATED DETECTIONS. Analyst review and tuning are required\n"
        " * before any operational use.\n"
        " */\n\n"
    )


def _escape_yara(s: str) -> str:
    """Escape a string for use inside YARA double quotes."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _uuid_from_sha(sha256: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_OID, sha256))


def _stable_uuid(kind: str, key: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"drake-x:dex:{kind}:{key}"))

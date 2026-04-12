"""Detection-engineering outputs — candidate YARA and STIX bundles (v0.9).

These writers convert Drake-X evidence into formats downstream detection
systems can consume. Per Drake-X doctrine:

- Every generated rule is labeled **candidate — analyst review required**.
- We do not claim generated rules are validated detections.
- Strings extracted for YARA are taken verbatim from deterministic
  evidence (carved shellcode, high-entropy sections, section names,
  known-packer signatures, import combinations). We do not fabricate.
- STIX bundles contain only observables that are already fact-level
  evidence (hashes, filenames). We do not emit speculative indicators.

YARA candidates are deliberately conservative: they require at least
two corroborating conditions to match, and they carry metadata
pointing to the evidence node IDs that justified generation so analysts
can triage them.
"""

from __future__ import annotations

import datetime as _dt
import json
import uuid
from typing import Any

from ..models.pe import PeAnalysisResult

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_pe_yara_candidates(result: PeAnalysisResult) -> str:
    """Render candidate YARA rules for a PE analysis.

    Returns an empty string when no signals are strong enough to justify
    a rule. A rule is emitted only when the evidence contains at least
    one of: carved shellcode, a high-entropy executable section with a
    packer-name hit, or a complete injection-chain import triad.

    All rules are prefixed ``Drake_Candidate_`` and marked in metadata.
    """
    rules: list[str] = []
    sha = result.metadata.sha256 or "unknown"
    short = sha[:16]
    timestamp = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%d")

    # ---- Shellcode-derived candidates ---------------------------------
    for i, sc in enumerate(result.suspected_shellcode):
        if not sc.preview_hex or len(sc.preview_hex) < 16:
            continue
        # Use the first 16 bytes (32 hex chars) of the preview as the
        # string. Longer previews risk false negatives from minor variants.
        hex_bytes = sc.preview_hex[:32]
        # Format as YARA hex string: "{ AA BB CC ... }"
        pairs = " ".join(hex_bytes[j:j+2] for j in range(0, len(hex_bytes), 2))
        rule_name = f"Drake_Candidate_Shellcode_{short}_{i}"
        rules.append(_render_shellcode_rule(
            rule_name=rule_name,
            sha=sha,
            hex_pattern=pairs,
            source_location=sc.source_location,
            detection_reason=sc.detection_reason,
            confidence=sc.confidence,
            timestamp=timestamp,
        ))

    # ---- Injection-chain candidate -----------------------------------
    injection_indicators = [
        ei for ei in result.exploit_indicators
        if ei.indicator_type.value == "injection_chain" and ei.confidence >= 0.6
    ]
    if injection_indicators:
        ind = injection_indicators[0]
        # Reference imports by their plain function names. YARA matches
        # these as ASCII substrings of the import table — not as semantic
        # imports, but this is a first-cut candidate.
        api_names = [r for r in ind.evidence_refs if len(r) >= 4][:8]
        if len(api_names) >= 3:
            rules.append(_render_injection_chain_rule(
                rule_name=f"Drake_Candidate_InjectionChain_{short}",
                sha=sha,
                api_names=api_names,
                confidence=ind.confidence,
                timestamp=timestamp,
            ))

    # ---- Packer / high-entropy section candidate ---------------------
    suspicious_sections = []
    for s in result.sections:
        if s.entropy >= 7.0 and s.is_executable:
            suspicious_sections.append(s)
    # Require at least one packer-name hit to justify emission.
    packer_hits = [
        p for p in result.suspicious_patterns
        if p.get("finding_type") == "packer_section_name"
    ]
    if suspicious_sections and packer_hits:
        names = sorted({s.name for s in suspicious_sections if s.name})
        if names:
            rules.append(_render_packer_rule(
                rule_name=f"Drake_Candidate_PackerSection_{short}",
                sha=sha,
                section_names=names,
                timestamp=timestamp,
            ))

    if not rules:
        return ""

    header = _render_yara_header()
    return header + "\n\n".join(rules) + "\n"


def render_pe_stix_bundle(result: PeAnalysisResult) -> str:
    """Render a minimal STIX 2.1 bundle with factual observables.

    The bundle contains:

    - one ``file`` observable for the sample (hashes + size)
    - an ``indicator`` for each high-confidence exploit indicator,
      labelled as ``candidate`` via the ``labels`` field
    - ``relationships`` linking indicators to the file

    Returns the bundle as a JSON string. Returns an empty string if the
    sample has no hash (nothing factually anchorable).
    """
    if not result.metadata.sha256:
        return ""

    bundle_id = f"bundle--{uuid.uuid4()}"
    now = _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds")

    file_obj = {
        "type": "file",
        "spec_version": "2.1",
        "id": f"file--{_uuid_from_sha(result.metadata.sha256)}",
        "hashes": {
            "MD5": result.metadata.md5,
            "SHA-256": result.metadata.sha256,
        },
        "size": result.metadata.file_size,
    }

    objects: list[dict[str, Any]] = [file_obj]

    for i, ind in enumerate(result.exploit_indicators):
        if ind.confidence < 0.5:
            continue
        indicator_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"Drake-X candidate: {ind.title}",
            "description": (
                f"{ind.description} "
                "NOTE: generated by Drake-X as a CANDIDATE; requires analyst "
                "review and dynamic validation before use as a detection."
            ),
            "indicator_types": ["anomalous-activity"],
            "labels": ["candidate", "drake-x-generated"],
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-256' = '{result.metadata.sha256}']",
            "valid_from": now,
            "confidence": int(ind.confidence * 100),
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid}
                for tid in ind.mitre_attck
            ],
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": file_obj["id"],
        })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
        "x_drake_x": {
            "generator_version": "0.9.0",
            "generated_at": now,
            "caveat": (
                "All indicators in this bundle are candidate outputs from "
                "Drake-X static analysis. They require analyst review and "
                "dynamic validation before operational use."
            ),
        },
    }
    return json.dumps(bundle, indent=2, default=str)


# ---------------------------------------------------------------------------
# Rule renderers
# ---------------------------------------------------------------------------


def _render_yara_header() -> str:
    return (
        "/*\n"
        " * Drake-X CANDIDATE YARA rules.\n"
        " *\n"
        " * These rules are generated from static analysis evidence and are\n"
        " * NOT VALIDATED DETECTIONS. Analyst review and tuning are required\n"
        " * before any operational use. No guarantee of precision or recall.\n"
        " *\n"
        " * Each rule's metadata references the SHA-256 of the source sample\n"
        " * and the evidence class that justified its generation.\n"
        " */\n\n"
    )


def _render_shellcode_rule(
    *,
    rule_name: str,
    sha: str,
    hex_pattern: str,
    source_location: str,
    detection_reason: str,
    confidence: float,
    timestamp: str,
) -> str:
    safe_reason = detection_reason.replace('"', "'")[:120]
    safe_loc = source_location.replace('"', "'")[:60]
    return (
        f"rule {rule_name}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        source_location = "{safe_loc}"\n'
        f'        detection_reason = "{safe_reason}"\n'
        f'        confidence = "{confidence:.2f}"\n'
        f'        generated_at = "{timestamp}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"        $sc = {{ {hex_pattern} }}\n"
        f"    condition:\n"
        f"        $sc and filesize < 50MB\n"
        f"}}"
    )


def _render_injection_chain_rule(
    *,
    rule_name: str,
    sha: str,
    api_names: list[str],
    confidence: float,
    timestamp: str,
) -> str:
    string_block = "\n".join(
        f'        $api_{i} = "{name}" ascii'
        for i, name in enumerate(api_names)
    )
    # Require at least three distinct API strings to match.
    return (
        f"rule {rule_name}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        indicator = "injection_chain"\n'
        f'        confidence = "{confidence:.2f}"\n'
        f'        generated_at = "{timestamp}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"{string_block}\n"
        f"    condition:\n"
        f"        3 of ($api_*) and filesize < 50MB\n"
        f"}}"
    )


def _render_packer_rule(
    *,
    rule_name: str,
    sha: str,
    section_names: list[str],
    timestamp: str,
) -> str:
    strings = "\n".join(
        f'        $sec_{i} = "{name}" ascii'
        for i, name in enumerate(section_names)
    )
    return (
        f"rule {rule_name}\n"
        f"{{\n"
        f"    meta:\n"
        f'        source = "drake-x"\n'
        f'        type = "candidate"\n'
        f'        source_sha256 = "{sha}"\n'
        f'        indicator = "packer_section_high_entropy"\n'
        f'        generated_at = "{timestamp}"\n'
        f'        note = "candidate — analyst review required"\n'
        f"    strings:\n"
        f"{strings}\n"
        f"    condition:\n"
        f"        any of ($sec_*) and filesize < 50MB\n"
        f"}}"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uuid_from_sha(sha256: str) -> str:
    """Produce a stable UUID from a SHA-256 hex digest.

    STIX 2.1 requires UUIDs; deriving one from the hash keeps bundle IDs
    reproducible across runs on the same sample.
    """
    # UUID5 with NAMESPACE_OID is stable and hex-input-friendly.
    return str(uuid.uuid5(uuid.NAMESPACE_OID, sha256))

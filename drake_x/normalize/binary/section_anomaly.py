"""PE section anomaly assessment.

Evaluates sections for packing indicators, suspicious characteristics,
and structural anomalies beyond what the parser's basic anomaly
detection covers.
"""

from __future__ import annotations

from typing import Any

from ...models.pe import PeSection


# Known packer section names
_PACKER_SECTIONS = {
    ".upx", ".upx0", ".upx1", ".upx2",  # UPX
    ".aspack", ".adata",                 # ASPack
    ".nsp0", ".nsp1",                    # NSPack
    ".perplex",                          # Perplex
    ".petite",                           # Petite
    ".yp",                               # Y0da Protector
    ".themida", ".winlice",              # Themida / WinLicense
    ".vmp0", ".vmp1",                    # VMProtect
    ".enigma1", ".enigma2",              # Enigma
    ".spack", ".svkp",                   # miscellaneous
    ".mpress",                           # MPRESS
}

_STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc",
    ".edata", ".idata", ".tls", ".pdata", ".gfids", ".crt",
    ".00cfg", ".retplne",
}


def assess_sections(sections: list[PeSection]) -> list[dict[str, Any]]:
    """Produce section-level assessment findings.

    Returns a list of assessment dicts with: section, finding_type,
    description, severity, confidence.
    """
    findings: list[dict[str, Any]] = []

    high_entropy_count = 0
    wx_count = 0

    for sec in sections:
        name_lower = sec.name.lower().strip()

        # Packer section name
        if name_lower in _PACKER_SECTIONS:
            findings.append({
                "section": sec.name,
                "finding_type": "packer_section_name",
                "description": f"Section '{sec.name}' matches known packer signature",
                "severity": "medium",
                "confidence": 0.8,
            })

        # High entropy
        if sec.entropy > 7.0:
            high_entropy_count += 1
            findings.append({
                "section": sec.name,
                "finding_type": "high_entropy",
                "description": f"Section '{sec.name}' entropy {sec.entropy:.2f} suggests compression or encryption",
                "severity": "medium",
                "confidence": 0.7,
            })

        # Writable + executable
        if sec.is_writable and sec.is_executable:
            wx_count += 1

        # Zero raw size with nonzero virtual size
        if sec.raw_size == 0 and sec.virtual_size > 0:
            findings.append({
                "section": sec.name,
                "finding_type": "zero_raw_size",
                "description": f"Section '{sec.name}' has zero raw size but {sec.virtual_size} virtual size — data allocated at runtime",
                "severity": "low",
                "confidence": 0.6,
            })

        # Non-standard name (not packer, not standard)
        if name_lower and name_lower not in _STANDARD_SECTIONS and name_lower not in _PACKER_SECTIONS:
            if not name_lower.startswith("."):
                findings.append({
                    "section": sec.name,
                    "finding_type": "non_standard_name",
                    "description": f"Section '{sec.name}' uses non-standard naming",
                    "severity": "info",
                    "confidence": 0.5,
                })

    # Aggregate assessments
    if high_entropy_count >= 2:
        findings.append({
            "section": "(aggregate)",
            "finding_type": "multiple_high_entropy",
            "description": f"{high_entropy_count} sections with high entropy — sample is likely packed or encrypted",
            "severity": "high",
            "confidence": 0.85,
        })

    if wx_count >= 2:
        findings.append({
            "section": "(aggregate)",
            "finding_type": "multiple_wx_sections",
            "description": f"{wx_count} sections are both writable and executable — unusual and suspicious",
            "severity": "high",
            "confidence": 0.9,
        })

    return findings

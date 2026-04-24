"""Heuristic pattern detectors for packed / obfuscated PE binaries (v1.3).

Certain malware families produce very thin static signal because the
operational payload is retrieved and decrypted at runtime. Examples:

  * **VB6 downloader stubs** (Emotet-era, Hancitor, Dridex-dropper
    variants): the sample is a minimal Visual Basic 6 program whose
    only purpose is to download and execute a second-stage payload.
    Its ``.text`` section is tiny, its sole imported DLL is
    ``MSVBVM60.DLL``, and no C2 URLs or commands are present as
    static strings because they are derived at runtime.

  * **.NET reflection-obfuscated binaries** (AgentTesla family,
    Formbook MSIL variants): the #US (user-strings) heap is stripped
    to zero entries and sensitive API calls are assembled at runtime
    via ``Microsoft.VisualBasic.CompilerServices.NewLateBinding.*``
    or ``System.Reflection.MethodInfo.Invoke``. Static import tables
    and MemberRef lists thus contain only runtime-invocation helpers,
    not the real target APIs.

These samples produce empty rule-based outputs not because the
technique is absent but because the *evidence is deliberately absent*.
This module detects the patterns themselves and emits findings that
cite the absence as the signal, with conservative confidence and
explicit ``requires_dynamic_validation=True`` annotation.

The outputs feed directly into ``PeAnalysisResult.suspicious_patterns``
and are consumed by the rule-based baseline via simple string-match
rules against the indicator type name.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# VB6 downloader-stub detection
# ---------------------------------------------------------------------------

def detect_vb6_downloader_stub(
    imports_dlls: list[str],
    imports_functions: list[str],
    sections: list[dict[str, Any]],
    strings_tagged: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Detect the VB6-runtime minimal-downloader pattern.

    Criteria (all must hold):
      - ``MSVBVM60.DLL`` is the sole or dominant imported DLL
      - The ``.text`` section is smaller than 100 KB
      - Fewer than 5 meaningful strings (URLs, IPs, domains, registry
        paths, ransom extensions) are tagged by the string extractor
    """
    dll_set = {d.upper() for d in (imports_dlls or []) if isinstance(d, str)}
    if "MSVBVM60.DLL" not in dll_set:
        return None
    # If the sample imports MSVBVM60 plus many other DLLs, it is a real
    # VB6 program with significant API surface — not a downloader stub.
    non_vb_dlls = dll_set - {"MSVBVM60.DLL"}
    if len(non_vb_dlls) > 0:
        return None

    text_size = 0
    for s in sections or []:
        name = (s.get("name", "") if isinstance(s, dict) else "")
        if name == ".text":
            text_size = int(s.get("raw_size", 0) or 0)
            break
    if not text_size or text_size > 100 * 1024:
        return None

    meaningful_categories = {
        "url", "domain", "ip", "email", "onion",
        "registry_run_key", "ransom_extension",
        "anti_recovery_vssadmin", "anti_recovery_bcdedit",
        "anti_recovery_wbadmin", "shell_cmd", "shell_powershell",
    }
    meaningful = sum(1 for s in (strings_tagged or [])
                    if isinstance(s, dict)
                    and s.get("category") in meaningful_categories)
    if meaningful >= 5:
        return None

    return {
        "indicator_type": "vb6_downloader_stub",
        "title": "VB6 runtime stub with minimal .text and no static C2 strings",
        "description": (
            f"Sample imports MSVBVM60.DLL as its sole DLL; .text section is "
            f"{text_size} bytes; only {meaningful} meaningful static strings. "
            "Canonical pattern for the Emotet-era VB6 downloader family: the "
            "operational payload is fetched and decrypted at runtime, so no "
            "C2 URLs, commands, or persistence tokens are visible statically."
        ),
        "severity": "high",
        "confidence": 0.70,
        "mitre_attck": ["T1105", "T1027", "T1140"],
        "evidence_refs": ["MSVBVM60.DLL (sole DLL)",
                           f".text size={text_size} bytes",
                           f"meaningful strings count={meaningful}"],
        "requires_dynamic_validation": True,
        "caveats": [
            "Static analysis cannot recover the second-stage payload without "
            "dynamic execution or sandboxed unpacking.",
            "The ATT&CK mappings reflect the family-class pattern, not "
            "techniques observed in this specific binary.",
        ],
    }


# ---------------------------------------------------------------------------
# .NET stripped-heap + reflection-obfuscation detection
# ---------------------------------------------------------------------------

_REFLECTION_MARKERS = (
    "NewLateBinding.LateGet",
    "NewLateBinding.LateIndexGet",
    "NewLateBinding.LateCall",
    "NewLateBinding.LateSet",
    "MethodInfo.Invoke",
    "Type.InvokeMember",
    "Type.GetMethod",
    "Type.GetField",
    "Assembly.Load",
    "Activator.CreateInstance",
)


def detect_dotnet_reflection_obfuscation(
    managed: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Detect .NET samples with stripped #US heap + heavy reflection use.

    Criteria (all must hold):
      - sample is a managed (.NET) binary
      - #US (user-strings) heap has zero entries
      - At least one reflection/late-binding marker is in MemberRefs
    """
    if not managed or not managed.get("is_dotnet"):
        return None
    user_strings = managed.get("user_strings") or []
    member_refs = managed.get("member_refs") or []
    if len(user_strings) > 0:
        return None
    hits = [m for m in member_refs
            if any(marker in m for marker in _REFLECTION_MARKERS)]
    if not hits:
        return None

    return {
        "indicator_type": "dotnet_reflection_obfuscation",
        "title": "Managed binary with stripped #US heap and reflection late-binding",
        "description": (
            f"The #US user-strings heap is empty; the binary references "
            f"{len(hits)} reflection/late-binding primitives "
            "(LateGet/LateCall/MethodInfo.Invoke/Type.GetMethod class). "
            "Consistent with AgentTesla-family MSIL obfuscation where "
            "sensitive types and API calls are assembled at runtime from "
            "encrypted resources, so static MemberRef inspection surfaces "
            "only the runtime-invocation harness."
        ),
        "severity": "high",
        "confidence": 0.80,
        "mitre_attck": ["T1027", "T1140", "T1407"],
        "evidence_refs": (["#US heap size=0"] +
                           [f"late-binding call: {m}" for m in hits[:5]]),
        "requires_dynamic_validation": True,
        "caveats": [
            "The actual operational technique set (typically infostealer "
            "behaviors: T1555, T1048.003, T1056.001, T1113) cannot be "
            "recovered without decrypting the managed resources or dynamic "
            "observation.",
            "Confidence reflects the pattern detection, not the specific "
            "downstream capability set.",
        ],
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def detect_all(
    imports_dlls: list[str],
    imports_functions: list[str],
    sections: list[dict[str, Any]],
    strings_tagged: list[dict[str, Any]],
    managed: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Run all detectors, returning a list of suspicious-pattern findings."""
    out: list[dict[str, Any]] = []
    vb6 = detect_vb6_downloader_stub(imports_dlls, imports_functions,
                                      sections, strings_tagged)
    if vb6:
        out.append(vb6)
    dotnet = detect_dotnet_reflection_obfuscation(managed)
    if dotnet:
        out.append(dotnet)
    return out

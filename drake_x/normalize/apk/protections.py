"""Detect anti-analysis protections from static artifacts.

For each protection type, returns a :class:`ProtectionIndicator` with
status ``observed``, ``suspected``, or ``not_observed`` plus supporting
evidence and safe analyst-oriented next steps.
"""

from __future__ import annotations

import re

from ...models.apk import ProtectionIndicator, ProtectionStatus


def detect_protections(
    *,
    smali_text: str = "",
    strings_text: str = "",
    java_text: str = "",
    manifest_text: str = "",
    native_lib_names: list[str] | None = None,
) -> list[ProtectionIndicator]:
    """Run all protection-detection heuristics."""
    corpus = "\n".join([smali_text, strings_text, java_text])
    indicators: list[ProtectionIndicator] = []

    indicators.append(_check_root_detection(corpus))
    indicators.append(_check_emulator_detection(corpus))
    indicators.append(_check_anti_debug(corpus))
    indicators.append(_check_frida_detection(corpus))
    indicators.append(_check_certificate_pinning(corpus, manifest_text))
    indicators.append(_check_native_protections(native_lib_names or [], smali_text))

    return indicators


def _check_root_detection(corpus: str) -> ProtectionIndicator:
    patterns = [
        r"su\b.*binary",
        r"/system/app/Superuser",
        r"com\.topjohnwu\.magisk",
        r"com\.noshufou\.android\.su",
        r"isRooted|rootBeer|RootTools|checkRoot",
        r"test-keys",
        r"/system/xbin/su",
    ]
    evidence = _match_patterns("root_detection", corpus, patterns)
    if len(evidence) >= 2:
        status = ProtectionStatus.OBSERVED
    elif evidence:
        status = ProtectionStatus.SUSPECTED
    else:
        status = ProtectionStatus.NOT_OBSERVED
    return ProtectionIndicator(
        protection_type="root_detection",
        status=status,
        evidence=evidence,
        analyst_next_steps=(
            "Confirm by running the sample in a rooted emulator and monitoring "
            "for root-check calls via Frida or equivalent instrumentation."
        ),
    )


def _check_emulator_detection(corpus: str) -> ProtectionIndicator:
    patterns = [
        r"Build\.(FINGERPRINT|MODEL|MANUFACTURER).*generic|goldfish|sdk",
        r"ro\.hardware.*goldfish",
        r"ro\.kernel\.qemu",
        r"isEmulator|EmulatorDetect",
        r"nox|bluestacks|genymotion",
        r"qemu.*pipe",
    ]
    evidence = _match_patterns("emulator_detection", corpus, patterns)
    status = ProtectionStatus.OBSERVED if len(evidence) >= 2 else (
        ProtectionStatus.SUSPECTED if evidence else ProtectionStatus.NOT_OBSERVED
    )
    return ProtectionIndicator(
        protection_type="emulator_detection",
        status=status,
        evidence=evidence,
        analyst_next_steps=(
            "Test in an emulator with anti-detection patches (e.g. hiding "
            "generic build properties) and observe behavioral differences."
        ),
    )


def _check_anti_debug(corpus: str) -> ProtectionIndicator:
    patterns = [
        r"android\.os\.Debug\.isDebuggerConnected",
        r"Debug\.isDebuggerConnected",
        r"ptrace",
        r"TracerPid",
        r"/proc/self/status.*TracerPid",
        r"android:debuggable.*false",
    ]
    evidence = _match_patterns("anti_debug", corpus, patterns)
    status = ProtectionStatus.OBSERVED if len(evidence) >= 2 else (
        ProtectionStatus.SUSPECTED if evidence else ProtectionStatus.NOT_OBSERVED
    )
    return ProtectionIndicator(
        protection_type="anti_debug",
        status=status,
        evidence=evidence,
        analyst_next_steps=(
            "Attach a debugger or use Frida to hook the detection methods and "
            "observe whether the app changes behavior."
        ),
    )


def _check_frida_detection(corpus: str) -> ProtectionIndicator:
    patterns = [
        r"frida",
        r"linjector",
        r"gmain.*frida",
        r"re\.frida\.server",
        r"27042",  # default frida port
        r"libfrida",
    ]
    evidence = _match_patterns("frida_detection", corpus, patterns)
    status = ProtectionStatus.OBSERVED if len(evidence) >= 2 else (
        ProtectionStatus.SUSPECTED if evidence else ProtectionStatus.NOT_OBSERVED
    )
    return ProtectionIndicator(
        protection_type="frida_detection",
        status=status,
        evidence=evidence,
        analyst_next_steps=(
            "Use a Frida gadget injection approach or rename/recompile Frida "
            "to bypass string-based detection."
        ),
    )


def _check_certificate_pinning(corpus: str, manifest: str) -> ProtectionIndicator:
    patterns = [
        r"CertificatePinner",
        r"network-security-config",
        r"sha256/[A-Za-z0-9+/=]{20,}",
        r"X509TrustManager",
        r"checkServerTrusted",
        r"SSLPeerUnverifiedException",
        r"pin-set",
    ]
    evidence = _match_patterns("certificate_pinning", corpus + "\n" + manifest, patterns)
    status = ProtectionStatus.OBSERVED if len(evidence) >= 2 else (
        ProtectionStatus.SUSPECTED if evidence else ProtectionStatus.NOT_OBSERVED
    )
    return ProtectionIndicator(
        protection_type="certificate_pinning",
        status=status,
        evidence=evidence,
        analyst_next_steps=(
            "Review network_security_config.xml if present. For dynamic "
            "analysis, use an SSL-unpinning Frida script."
        ),
    )


def _check_native_protections(lib_names: list[str], smali: str) -> ProtectionIndicator:
    evidence: list[str] = []
    suspicious_libs = [n for n in lib_names if re.search(
        r'libjiagu|libsecexe|libprotect|libshell|libDexHelper', n, re.I
    )]
    if suspicious_libs:
        evidence.append(f"Suspicious native libraries: {', '.join(suspicious_libs)}")
    native_count = len(re.findall(r'\.method.*native\b', smali))
    if native_count > 20:
        evidence.append(f"{native_count} native method declarations (heavy JNI usage)")

    status = ProtectionStatus.OBSERVED if len(evidence) >= 2 else (
        ProtectionStatus.SUSPECTED if evidence else ProtectionStatus.NOT_OBSERVED
    )
    return ProtectionIndicator(
        protection_type="native_protections",
        status=status,
        evidence=evidence,
        analyst_next_steps=(
            "Use Ghidra or radare2 to reverse-engineer the native libraries. "
            "Look for anti-tampering checks, decryption routines, or VM-based "
            "protection logic."
        ),
    )


def _match_patterns(label: str, corpus: str, patterns: list[str]) -> list[str]:
    evidence: list[str] = []
    for pat in patterns:
        m = re.search(pat, corpus, re.I)
        if m:
            start = max(0, m.start() - 30)
            end = min(len(corpus), m.end() + 30)
            snippet = corpus[start:end].replace("\n", " ").strip()[:120]
            evidence.append(f"[{label}] matched: {snippet}")
    return evidence

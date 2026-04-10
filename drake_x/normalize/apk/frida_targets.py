"""Generate Frida dynamic validation targets from static analysis evidence.

This module does NOT generate bypass scripts. It produces a structured
list of hook candidates that an analyst can use to plan dynamic
validation in a controlled environment.

For each candidate:

- ``target_class`` / ``target_method`` — the Java/JNI symbol to hook
- ``protection_type`` — the protection or behavior it relates to
- ``evidence_basis`` — static evidence that led to this suggestion
- ``expected_observation`` — what the analyst should observe when hooking
- ``suggested_validation_objective`` — what the hook would help confirm
- ``analyst_notes`` — additional context for the analyst
- ``priority`` — high/medium/low based on evidence strength
- ``confidence`` — 0.0–1.0

Every suggestion is backed by evidence from the static analysis. Nothing
is invented.
"""

from __future__ import annotations

from ...models.apk import (
    ApkAnalysisResult,
    BehaviorIndicator,
    FridaHookTarget,
    ProtectionIndicator,
    ProtectionStatus,
)


def generate_frida_targets(result: ApkAnalysisResult) -> list[FridaHookTarget]:
    """Generate hook candidates from protections and behavior indicators."""
    targets: list[FridaHookTarget] = []

    # From protection indicators
    for pi in result.protection_indicators:
        if pi.status == ProtectionStatus.NOT_OBSERVED:
            continue
        targets.extend(_targets_from_protection(pi))

    # From behavior indicators (dynamic loading, dropper, exfiltration)
    for bi in result.behavior_indicators:
        targets.extend(_targets_from_behavior(bi))

    return targets


def _targets_from_protection(pi: ProtectionIndicator) -> list[FridaHookTarget]:
    """Map a detected protection to specific hook candidates."""
    targets: list[FridaHookTarget] = []
    conf = 0.8 if pi.status == ProtectionStatus.OBSERVED else 0.5
    prio = "high" if pi.status == ProtectionStatus.OBSERVED else "medium"

    if pi.protection_type == "root_detection":
        targets.append(FridaHookTarget(
            target_class="java.io.File",
            target_method="exists",
            protection_type="root_detection",
            evidence_basis=pi.evidence,
            expected_observation="Returns true for /system/xbin/su or similar paths",
            suggested_validation_objective="Confirm whether the app checks for root binaries and alters behavior",
            analyst_notes="Hook File.exists() and log the path argument. If su-related paths are checked, the app likely has root detection.",
            priority=prio,
            confidence=conf,
        ))
        targets.append(FridaHookTarget(
            target_class="android.os.Build",
            target_method="TAGS (field read)",
            protection_type="root_detection",
            evidence_basis=pi.evidence,
            expected_observation="Build.TAGS contains 'test-keys' on rooted devices",
            suggested_validation_objective="Confirm whether the app inspects Build.TAGS for test-keys",
            analyst_notes="Monitor reads of Build.TAGS to determine if the app uses this as a root indicator.",
            priority="medium",
            confidence=conf * 0.8,
        ))

    elif pi.protection_type == "emulator_detection":
        targets.append(FridaHookTarget(
            target_class="android.os.Build",
            target_method="FINGERPRINT / MODEL / MANUFACTURER (field reads)",
            protection_type="emulator_detection",
            evidence_basis=pi.evidence,
            expected_observation="Build properties contain 'generic', 'sdk', 'goldfish', or emulator-specific values",
            suggested_validation_objective="Confirm whether the app compares build properties against emulator signatures",
            analyst_notes="Hook property reads and log values. Compare behavior in emulator vs physical device.",
            priority=prio,
            confidence=conf,
        ))

    elif pi.protection_type == "anti_debug":
        targets.append(FridaHookTarget(
            target_class="android.os.Debug",
            target_method="isDebuggerConnected",
            protection_type="anti_debug",
            evidence_basis=pi.evidence,
            expected_observation="Returns true when a debugger is attached",
            suggested_validation_objective="Confirm whether the app checks for debugger attachment and alters behavior",
            analyst_notes="Hook isDebuggerConnected() to always return false, then observe if hidden behavior activates.",
            priority=prio,
            confidence=conf,
        ))

    elif pi.protection_type == "frida_detection":
        targets.append(FridaHookTarget(
            target_class="java.io.File",
            target_method="exists",
            protection_type="frida_detection",
            evidence_basis=pi.evidence,
            expected_observation="Checks for frida-server binaries or /tmp/frida-* artifacts",
            suggested_validation_objective="Confirm whether the app scans for Frida artifacts on the filesystem",
            analyst_notes="Log File.exists() calls matching 'frida'. Consider renaming Frida binaries or using a Frida gadget approach.",
            priority=prio,
            confidence=conf,
        ))

    elif pi.protection_type == "certificate_pinning":
        targets.append(FridaHookTarget(
            target_class="okhttp3.CertificatePinner",
            target_method="check",
            protection_type="certificate_pinning",
            evidence_basis=pi.evidence,
            expected_observation="Throws SSLPeerUnverifiedException when cert doesn't match pins",
            suggested_validation_objective="Confirm whether the app enforces certificate pinning and inspect pinned hosts",
            analyst_notes="Hook CertificatePinner.check() to observe pinned hostnames. Use an SSL unpinning script to enable traffic interception if authorized.",
            priority=prio,
            confidence=conf,
        ))
        targets.append(FridaHookTarget(
            target_class="javax.net.ssl.X509TrustManager",
            target_method="checkServerTrusted",
            protection_type="certificate_pinning",
            evidence_basis=pi.evidence,
            expected_observation="Custom trust manager validates server certificates",
            suggested_validation_objective="Determine if a custom trust manager is used and what certificates it accepts",
            analyst_notes="Hook checkServerTrusted() to log the certificate chain and determine pinning behavior.",
            priority="medium",
            confidence=conf * 0.8,
        ))

    elif pi.protection_type == "native_protections":
        targets.append(FridaHookTarget(
            target_class="java.lang.System",
            target_method="loadLibrary",
            protection_type="native_protections",
            evidence_basis=pi.evidence,
            expected_observation="Loads native libraries that may contain anti-analysis logic",
            suggested_validation_objective="Identify which native libraries are loaded and monitor JNI_OnLoad behavior",
            analyst_notes="Hook System.loadLibrary() to log library names. Follow up with Ghidra analysis of suspicious .so files.",
            priority=prio,
            confidence=conf,
        ))

    return targets


def _targets_from_behavior(bi: BehaviorIndicator) -> list[FridaHookTarget]:
    """Map a behavior indicator to validation hook candidates."""
    targets: list[FridaHookTarget] = []

    if bi.category == "dynamic_loading" and "DexClassLoader" in bi.pattern:
        targets.append(FridaHookTarget(
            target_class="dalvik.system.DexClassLoader",
            target_method="<init>",
            protection_type="dynamic_loading",
            evidence_basis=[bi.evidence],
            expected_observation="Constructor receives a path to a DEX file to load at runtime",
            suggested_validation_objective="Capture the DEX file path and extract the payload for static analysis",
            analyst_notes="Hook the DexClassLoader constructor to log the dexPath argument. The loaded DEX may contain the real malicious logic.",
            priority="high",
            confidence=bi.confidence,
        ))

    if bi.category == "dropper" and "PackageInstaller" in bi.pattern:
        targets.append(FridaHookTarget(
            target_class="android.content.pm.PackageInstaller",
            target_method="createSession",
            protection_type="dropper_behavior",
            evidence_basis=[bi.evidence],
            expected_observation="Creates an install session to sideload a secondary APK",
            suggested_validation_objective="Capture the session parameters and the APK being installed",
            analyst_notes="Hook createSession() and openSession() to intercept the install flow. Extract the secondary APK for analysis.",
            priority="high",
            confidence=bi.confidence,
        ))

    if bi.category == "exfiltration" and "AccessibilityService" in bi.pattern:
        targets.append(FridaHookTarget(
            target_class="android.accessibilityservice.AccessibilityService",
            target_method="onAccessibilityEvent",
            protection_type="accessibility_abuse",
            evidence_basis=[bi.evidence],
            expected_observation="Receives accessibility events — may be used for keylogging or UI manipulation",
            suggested_validation_objective="Monitor which event types are handled and what data is extracted",
            analyst_notes="Hook onAccessibilityEvent() to log event types and source package names. Look for overlay attacks or credential harvesting.",
            priority="high",
            confidence=bi.confidence,
        ))

    if bi.category == "communication" and "Firebase" in bi.pattern:
        targets.append(FridaHookTarget(
            target_class="com.google.firebase.messaging.FirebaseMessagingService",
            target_method="onMessageReceived",
            protection_type="c2_communication",
            evidence_basis=[bi.evidence],
            expected_observation="Receives FCM push messages that may contain C2 commands",
            suggested_validation_objective="Capture incoming FCM message payloads and determine if they trigger malicious behavior",
            analyst_notes="Hook onMessageReceived() to log RemoteMessage contents. FCM is commonly abused as a C2 channel by mobile malware.",
            priority="high",
            confidence=bi.confidence,
        ))

    return targets

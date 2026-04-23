"""Sensitive API detector — identify usage of security-relevant Android APIs.

Each detector is a compiled regex pattern with metadata about the API
category, ATT&CK mapping, and default severity. The detector scans text
corpora (decompiled Java, smali, or raw strings) and produces structured
:class:`SensitiveApiHit` findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..logging import get_logger
from ..models.dex import DexFindingSeverity, SensitiveApiCategory, SensitiveApiHit

log = get_logger("dex.sensitive_apis")

_MAX_SNIPPET = 200


@dataclass(frozen=True)
class _ApiPattern:
    category: SensitiveApiCategory
    api_name: str
    regex: re.Pattern[str]
    confidence: float = 0.7
    severity: DexFindingSeverity = DexFindingSeverity.MEDIUM
    mitre_attck: tuple[str, ...] = ()
    notes: str = ""


_PATTERNS: list[_ApiPattern] = [
    # --- AccessibilityService ---
    _ApiPattern(
        SensitiveApiCategory.ACCESSIBILITY,
        "AccessibilityService",
        re.compile(r"AccessibilityService|onAccessibilityEvent|AccessibilityNodeInfo"),
        confidence=0.85,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1517",),
        notes="Overlay/keylogger vector",
    ),
    _ApiPattern(
        SensitiveApiCategory.ACCESSIBILITY,
        "performAction",
        re.compile(r"performAction\(|ACTION_CLICK|ACTION_SCROLL"),
        confidence=0.75,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1517",),
    ),

    # --- PackageInstaller ---
    _ApiPattern(
        SensitiveApiCategory.PACKAGE_INSTALLER,
        "PackageInstaller",
        re.compile(r"PackageInstaller|createSession|openSession.*install"),
        confidence=0.85,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1398",),
        notes="Sideload / dropper flow",
    ),
    _ApiPattern(
        SensitiveApiCategory.PACKAGE_INSTALLER,
        "ACTION_INSTALL_PACKAGE",
        re.compile(r"ACTION_INSTALL_PACKAGE|REQUEST_INSTALL_PACKAGES"),
        confidence=0.8,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1398",),
    ),

    # --- FileProvider ---
    _ApiPattern(
        SensitiveApiCategory.FILE_PROVIDER,
        "FileProvider",
        re.compile(r"FileProvider|getUriForFile"),
        confidence=0.5,
        severity=DexFindingSeverity.LOW,
    ),

    # --- WebView ---
    _ApiPattern(
        SensitiveApiCategory.WEBVIEW,
        "WebView.loadUrl",
        re.compile(r"WebView|loadUrl\(|loadData\(|addJavascriptInterface"),
        confidence=0.6,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1185",),
    ),
    _ApiPattern(
        SensitiveApiCategory.WEBVIEW,
        "JavaScript bridge",
        re.compile(r"addJavascriptInterface|@JavascriptInterface|evaluateJavascript"),
        confidence=0.75,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1185",),
        notes="JS-to-native bridge — potential RCE if content is attacker-controlled",
    ),
    _ApiPattern(
        SensitiveApiCategory.WEBVIEW,
        "setJavaScriptEnabled",
        re.compile(r"setJavaScriptEnabled\s*\(\s*true"),
        confidence=0.6,
        severity=DexFindingSeverity.MEDIUM,
    ),

    # --- SMS ---
    _ApiPattern(
        SensitiveApiCategory.SMS,
        "SmsManager",
        re.compile(r"SmsManager|sendTextMessage|sendMultipartTextMessage"),
        confidence=0.85,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1582.001",),
    ),
    _ApiPattern(
        SensitiveApiCategory.SMS,
        "SMS content provider",
        re.compile(r"content://sms|Telephony\.Sms"),
        confidence=0.8,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1636.004",),
    ),

    # --- TelephonyManager ---
    _ApiPattern(
        SensitiveApiCategory.TELEPHONY,
        "TelephonyManager",
        re.compile(r"TelephonyManager|getDeviceId|getImei|getSubscriberId|getLine1Number"),
        confidence=0.75,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1426",),
    ),

    # --- DevicePolicyManager (device admin) ---
    _ApiPattern(
        SensitiveApiCategory.DEVICE_ADMIN,
        "DevicePolicyManager",
        re.compile(r"DevicePolicyManager|BIND_DEVICE_ADMIN|lockNow|wipeData|resetPassword"),
        confidence=0.85,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1401",),
        notes="Device admin abuse — lock, wipe, or credential tampering",
    ),

    # --- Runtime.exec ---
    _ApiPattern(
        SensitiveApiCategory.RUNTIME_EXEC,
        "Runtime.exec",
        re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder"),
        confidence=0.8,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1059.004",),
        notes="Arbitrary command execution",
    ),
    _ApiPattern(
        SensitiveApiCategory.RUNTIME_EXEC,
        "su / root check",
        re.compile(r'"su"|/system/xbin/su|/system/bin/su|test-keys'),
        confidence=0.7,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1404",),
    ),

    # --- DexClassLoader / dynamic loading ---
    _ApiPattern(
        SensitiveApiCategory.DEX_LOADING,
        "DexClassLoader",
        re.compile(r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader"),
        confidence=0.9,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1407",),
        notes="Dynamic DEX loading — payload delivery vector",
    ),
    _ApiPattern(
        SensitiveApiCategory.DEX_LOADING,
        "DexFile API",
        re.compile(r"dalvik[./]system[./]DexFile|loadDex\("),
        confidence=0.85,
        severity=DexFindingSeverity.HIGH,
        mitre_attck=("T1407",),
    ),

    # --- Reflection ---
    _ApiPattern(
        SensitiveApiCategory.REFLECTION,
        "Class.forName",
        re.compile(r"Class\.forName\(|\.forName\("),
        confidence=0.6,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1620",),
    ),
    _ApiPattern(
        SensitiveApiCategory.REFLECTION,
        "Method.invoke",
        re.compile(r"Method\.invoke\(|\.invoke\(.*Method"),
        confidence=0.65,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1620",),
    ),
    _ApiPattern(
        SensitiveApiCategory.REFLECTION,
        "getDeclaredMethod/Field",
        re.compile(r"getDeclaredMethod|getDeclaredField|getDeclaredConstructor"),
        confidence=0.6,
        severity=DexFindingSeverity.MEDIUM,
    ),

    # --- Crypto ---
    _ApiPattern(
        SensitiveApiCategory.CRYPTO,
        "Cipher API",
        re.compile(r"Cipher\.getInstance|javax\.crypto|SecretKeySpec|KeyGenerator"),
        confidence=0.5,
        severity=DexFindingSeverity.LOW,
    ),
    _ApiPattern(
        SensitiveApiCategory.CRYPTO,
        "AES/DES usage",
        re.compile(r'"AES"|"DES"|"RSA"|"Blowfish"|"RC4"'),
        confidence=0.5,
        severity=DexFindingSeverity.INFO,
    ),

    # --- Camera ---
    _ApiPattern(
        SensitiveApiCategory.CAMERA,
        "Camera access",
        re.compile(r"CameraManager|camera2|takePicture|captureStillImage"),
        confidence=0.7,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1512",),
    ),

    # --- Location ---
    _ApiPattern(
        SensitiveApiCategory.LOCATION,
        "Location tracking",
        re.compile(r"LocationManager|getLastKnownLocation|requestLocationUpdates|FusedLocationProvider"),
        confidence=0.65,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1430",),
    ),

    # --- Clipboard ---
    _ApiPattern(
        SensitiveApiCategory.CLIPBOARD,
        "Clipboard access",
        re.compile(r"ClipboardManager|getPrimaryClip|setPrimaryClip"),
        confidence=0.7,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1414",),
    ),

    # --- Contacts ---
    _ApiPattern(
        SensitiveApiCategory.CONTACTS,
        "Contacts access",
        re.compile(r"ContactsContract|content://contacts|content://com\.android\.contacts"),
        confidence=0.75,
        severity=DexFindingSeverity.MEDIUM,
        mitre_attck=("T1636.003",),
    ),

    # --- Network ---
    _ApiPattern(
        SensitiveApiCategory.NETWORK,
        "HTTP client",
        re.compile(r"HttpURLConnection|HttpsURLConnection|OkHttpClient|okhttp3"),
        confidence=0.3,
        severity=DexFindingSeverity.INFO,
    ),
]


def detect_sensitive_apis(
    text: str,
    *,
    source_dex: str = "",
    source_label: str = "",
) -> list[SensitiveApiHit]:
    """Scan *text* for sensitive API usage patterns.

    Parameters
    ----------
    text:
        Decompiled Java source, smali bytecode, or extracted strings.
    source_dex:
        Originating DEX file name for provenance.
    source_label:
        Additional context (e.g., file path within decompiled output).
    """
    hits: list[SensitiveApiHit] = []
    seen: set[tuple[str, str]] = set()

    for pattern in _PATTERNS:
        for match in pattern.regex.finditer(text):
            key = (pattern.api_name, match.group(0)[:80])
            if key in seen:
                continue
            seen.add(key)

            snippet = _extract_snippet(text, match.start())

            hits.append(SensitiveApiHit(
                api_category=pattern.category,
                api_name=pattern.api_name,
                source_dex=source_dex,
                raw_match=snippet,
                confidence=pattern.confidence,
                severity=pattern.severity,
                mitre_attck=list(pattern.mitre_attck),
                notes=pattern.notes,
            ))

    log.debug(
        "Detected %d sensitive API hit(s) in %s",
        len(hits), source_dex or source_label or "input",
    )
    return hits


def _extract_snippet(text: str, pos: int) -> str:
    """Extract a context snippet around the match position."""
    start = max(0, pos - 40)
    end = min(len(text), pos + _MAX_SNIPPET - 40)
    snippet = text[start:end].strip()
    # Collapse whitespace
    snippet = re.sub(r"\s+", " ", snippet)
    return snippet[:_MAX_SNIPPET]

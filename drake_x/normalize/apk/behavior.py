"""Static behavior analysis — scan source/smali/strings for suspicious patterns.

Every pattern is a compiled regex + a category + a confidence. The analyzer
scans the provided text corpus and produces :class:`BehaviorIndicator` rows
for each match.

Categories:
- dynamic_loading — DexClassLoader, reflection-heavy patterns
- dropper — PackageInstaller, session install flow
- persistence — BOOT_COMPLETED, foreground services, alarms
- exfiltration — contacts, SMS, clipboard, accessibility, device IDs
- communication — URLs, Firebase/FCM, WebView, HTTP clients
- social_engineering — fake update strings, deceptive UI
- trigger_logic — user-click triggers, FCM push, preference flags,
  time/device/env checks
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...models.apk import BehaviorIndicator

_MAX_EXCERPT = 200


@dataclass(frozen=True)
class _Pattern:
    category: str
    label: str
    regex: re.Pattern[str]
    confidence: float = 0.7


_PATTERNS: list[_Pattern] = [
    # dynamic loading
    _Pattern("dynamic_loading", "DexClassLoader", re.compile(r"DexClassLoader", re.I), 0.9),
    _Pattern("dynamic_loading", "InMemoryDexClassLoader", re.compile(r"InMemoryDexClassLoader", re.I), 0.9),
    _Pattern("dynamic_loading", "PathClassLoader", re.compile(r"PathClassLoader", re.I), 0.7),
    _Pattern("dynamic_loading", "dalvik.system.DexFile", re.compile(r"dalvik[./]system[./]DexFile", re.I), 0.8),
    _Pattern("dynamic_loading", "Class.forName reflection", re.compile(r"Class\.forName\("), 0.6),
    _Pattern("dynamic_loading", "loadClass reflection", re.compile(r"\.loadClass\("), 0.6),
    _Pattern("dynamic_loading", "Runtime.getRuntime().exec", re.compile(r"Runtime\.getRuntime\(\)\.exec"), 0.8),

    # dropper / installer
    _Pattern("dropper", "PackageInstaller", re.compile(r"PackageInstaller"), 0.85),
    _Pattern("dropper", "ACTION_INSTALL_PACKAGE", re.compile(r"ACTION_INSTALL_PACKAGE"), 0.85),
    _Pattern("dropper", "createSession install", re.compile(r"createSession|openSession.*install", re.I), 0.75),
    _Pattern("dropper", "REQUEST_INSTALL_PACKAGES intent", re.compile(r"REQUEST_INSTALL_PACKAGES"), 0.8),

    # persistence
    _Pattern("persistence", "BOOT_COMPLETED receiver", re.compile(r"BOOT_COMPLETED"), 0.8),
    _Pattern("persistence", "AlarmManager", re.compile(r"AlarmManager"), 0.5),
    _Pattern("persistence", "WorkManager / JobScheduler", re.compile(r"WorkManager|JobScheduler|JobService"), 0.5),
    _Pattern("persistence", "startForeground", re.compile(r"startForeground"), 0.6),
    _Pattern("persistence", "WakeLock", re.compile(r"WakeLock|PARTIAL_WAKE_LOCK"), 0.5),

    # exfiltration indicators
    _Pattern("exfiltration", "getDeviceId / IMEI", re.compile(r"getDeviceId|TelephonyManager"), 0.7),
    _Pattern("exfiltration", "ContentResolver contacts", re.compile(r"ContactsContract|content://contacts"), 0.8),
    _Pattern("exfiltration", "SMS read/send", re.compile(r"SmsManager|content://sms"), 0.85),
    _Pattern("exfiltration", "clipboard access", re.compile(r"ClipboardManager|getPrimaryClip"), 0.7),
    _Pattern("exfiltration", "AccessibilityService abuse", re.compile(r"AccessibilityService|onAccessibilityEvent"), 0.85),
    _Pattern("exfiltration", "KeyLogger pattern", re.compile(r"onKey|dispatchKeyEvent.*log", re.I), 0.6),
    _Pattern("exfiltration", "Location access", re.compile(r"LocationManager|getLastKnownLocation|requestLocationUpdates"), 0.6),
    _Pattern("exfiltration", "Camera capture", re.compile(r"CameraManager|takePicture"), 0.7),

    # external communication
    _Pattern("communication", "Firebase / FCM", re.compile(r"FirebaseMessaging|FirebaseInstanceId|google-services|fcm"), 0.7),
    _Pattern("communication", "WebView loadUrl", re.compile(r"WebView.*loadUrl|\.loadUrl\("), 0.5),
    _Pattern("communication", "OkHttp / Retrofit", re.compile(r"OkHttpClient|Retrofit|okhttp3"), 0.4),
    _Pattern("communication", "HttpURLConnection", re.compile(r"HttpURLConnection|HttpsURLConnection"), 0.4),
    _Pattern("communication", "Volley", re.compile(r"com\.android\.volley|RequestQueue"), 0.4),

    # social engineering
    _Pattern("social_engineering", "fake update string", re.compile(r"update.*required|system.*update|security.*update", re.I), 0.6),
    _Pattern("social_engineering", "Google Play branding", re.compile(r"Google\s*Play|play\.google\.com", re.I), 0.5),
    _Pattern("social_engineering", "banking / credential phishing", re.compile(r"card.*number|cvv|expir|login.*bank", re.I), 0.7),

    # trigger / hidden logic
    _Pattern("trigger_logic", "SharedPreferences flag", re.compile(r"SharedPreferences.*edit\(\)|getBoolean|putBoolean", re.I), 0.3),
    _Pattern("trigger_logic", "SIM operator / locale check", re.compile(r"getSimOperator|getNetworkOperator|Locale\.getDefault"), 0.6),
    _Pattern("trigger_logic", "time-based trigger", re.compile(r"System\.currentTimeMillis|Calendar\.getInstance.*HOUR", re.I), 0.4),
]


def analyze_behavior(text_corpus: str, *, source_label: str = "") -> list[BehaviorIndicator]:
    """Scan *text_corpus* for suspicious behavior patterns.

    *source_label* is attached to each indicator so the report can point
    back to the file that produced the match.
    """
    indicators: list[BehaviorIndicator] = []
    seen: set[str] = set()

    for pat in _PATTERNS:
        m = pat.regex.search(text_corpus)
        if m is None:
            continue
        key = f"{pat.category}:{pat.label}"
        if key in seen:
            continue
        seen.add(key)

        start = max(0, m.start() - 40)
        end = min(len(text_corpus), m.end() + 40)
        excerpt = text_corpus[start:end].replace("\n", " ").strip()
        if len(excerpt) > _MAX_EXCERPT:
            excerpt = excerpt[:_MAX_EXCERPT] + "..."

        indicators.append(BehaviorIndicator(
            category=pat.category,
            pattern=pat.label,
            evidence=excerpt,
            source_file=source_label,
            confidence=pat.confidence,
        ))

    return indicators

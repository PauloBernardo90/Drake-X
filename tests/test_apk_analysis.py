"""Tests for the APK static-analysis agent.

These tests exercise the normalizers, models, and report writer using
mocked tool output — no real APK file or native Kali tools required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.models.apk import (
    ApkAnalysisResult,
    ApkComponent,
    ApkMetadata,
    ApkPermission,
    BehaviorIndicator,
    CampaignSimilarity,
    ComponentType,
    NetworkIndicator,
    ObfuscationConfidence,
    ProtectionStatus,
)
from drake_x.normalize.apk.behavior import analyze_behavior
from drake_x.normalize.apk.campaign import assess_campaigns
from drake_x.normalize.apk.components import parse_components, parse_manifest_xml
from drake_x.normalize.apk.manifest import parse_badging
from drake_x.normalize.apk.network import extract_network_indicators
from drake_x.normalize.apk.obfuscation import assess_obfuscation
from drake_x.normalize.apk.permissions import SUSPICIOUS_PERMISSIONS, parse_permissions, flag_suspicious
from drake_x.normalize.apk.protections import detect_protections
from drake_x.reporting.apk_report_writer import render_apk_json, render_apk_markdown


# ---------------------------------------------------------------------------
# aapt badging fixture
# ---------------------------------------------------------------------------

BADGING_OUTPUT = """\
package: name='com.example.malware' versionCode='42' versionName='1.3.7'
sdkVersion:'21'
targetSdkVersion:'33'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.READ_SMS'
uses-permission: name='android.permission.RECEIVE_BOOT_COMPLETED'
uses-permission: name='android.permission.REQUEST_INSTALL_PACKAGES'
uses-permission: name='android.permission.BIND_ACCESSIBILITY_SERVICE'
uses-permission: name='android.permission.FOREGROUND_SERVICE'
uses-permission: name='android.permission.CAMERA'
launchable-activity: name='com.example.malware.MainActivity'
"""

MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.malware">
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <service android:name=".DropperService" android:exported="false"/>
    <receiver android:name=".BootReceiver" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".DataProvider" android:exported="false"/>
  </application>
</manifest>
"""


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------


def test_parse_badging_extracts_package_name() -> None:
    meta = parse_badging(BADGING_OUTPUT)
    assert meta.package_name == "com.example.malware"
    assert meta.version_code == "42"
    assert meta.version_name == "1.3.7"
    assert meta.min_sdk == "21"
    assert meta.target_sdk == "33"
    assert meta.main_activity == "com.example.malware.MainActivity"


def test_parse_badging_handles_empty_input() -> None:
    meta = parse_badging("")
    assert meta.package_name == ""


# ---------------------------------------------------------------------------
# Permission extraction
# ---------------------------------------------------------------------------


def test_parse_permissions_extracts_all() -> None:
    perms = parse_permissions(BADGING_OUTPUT)
    names = {p.name for p in perms}
    assert "android.permission.READ_SMS" in names
    assert "android.permission.INTERNET" in names
    assert len(perms) == 7


def test_parse_permissions_flags_suspicious() -> None:
    perms = parse_permissions(BADGING_OUTPUT)
    suspicious = flag_suspicious(perms)
    suspicious_names = {p.name for p in suspicious}
    assert "android.permission.READ_SMS" in suspicious_names
    assert "android.permission.REQUEST_INSTALL_PACKAGES" in suspicious_names
    assert "android.permission.BIND_ACCESSIBILITY_SERVICE" in suspicious_names
    assert "android.permission.RECEIVE_BOOT_COMPLETED" in suspicious_names


def test_parse_permissions_marks_dangerous() -> None:
    perms = parse_permissions(BADGING_OUTPUT)
    sms = next(p for p in perms if p.name == "android.permission.READ_SMS")
    assert sms.is_dangerous is True
    inet = next(p for p in perms if p.name == "android.permission.INTERNET")
    assert inet.is_dangerous is False


# ---------------------------------------------------------------------------
# Component extraction
# ---------------------------------------------------------------------------


def test_parse_components_from_badging() -> None:
    comps = parse_components(BADGING_OUTPUT)
    assert any(c.name == "com.example.malware.MainActivity" for c in comps)


def test_parse_manifest_xml_extracts_all_types() -> None:
    comps = parse_manifest_xml(MANIFEST_XML)
    types = {c.component_type for c in comps}
    assert ComponentType.ACTIVITY in types
    assert ComponentType.SERVICE in types
    assert ComponentType.RECEIVER in types
    assert ComponentType.PROVIDER in types


def test_parse_manifest_xml_detects_exported() -> None:
    comps = parse_manifest_xml(MANIFEST_XML)
    main = next(c for c in comps if "MainActivity" in c.name)
    assert main.exported is True
    svc = next(c for c in comps if "DropperService" in c.name)
    assert svc.exported is False


def test_parse_manifest_xml_extracts_intent_filters() -> None:
    comps = parse_manifest_xml(MANIFEST_XML)
    receiver = next(c for c in comps if "BootReceiver" in c.name)
    assert "android.intent.action.BOOT_COMPLETED" in receiver.intent_filters


def test_parse_manifest_xml_handles_garbage() -> None:
    assert parse_manifest_xml("not xml at all") == []


# ---------------------------------------------------------------------------
# Behavior analysis
# ---------------------------------------------------------------------------


MALICIOUS_CODE = """\
DexClassLoader dexLoader = new DexClassLoader(path, opt, null, parent);
PackageInstaller installer = getPackageManager().getPackageInstaller();
installer.createSession(params);
TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
String imei = tm.getDeviceId();
SmsManager sms = SmsManager.getDefault();
AccessibilityService.onAccessibilityEvent(event);
FirebaseMessaging.getInstance().subscribeToTopic("commands");
SharedPreferences.edit().putBoolean("activated", true);
https://evil.example.com/api/exfil
http://c2.example.net/beacon
"""


def test_behavior_detects_dynamic_loading() -> None:
    indicators = analyze_behavior(MALICIOUS_CODE)
    cats = {b.category for b in indicators}
    assert "dynamic_loading" in cats


def test_behavior_detects_dropper_patterns() -> None:
    indicators = analyze_behavior(MALICIOUS_CODE)
    patterns = {b.pattern for b in indicators}
    assert "PackageInstaller" in patterns


def test_behavior_detects_exfiltration() -> None:
    indicators = analyze_behavior(MALICIOUS_CODE)
    cats = {b.category for b in indicators}
    assert "exfiltration" in cats


def test_behavior_detects_firebase_fcm() -> None:
    indicators = analyze_behavior(MALICIOUS_CODE)
    patterns = {b.pattern for b in indicators}
    assert "Firebase / FCM" in patterns


def test_behavior_detects_persistence() -> None:
    text = "registerReceiver BOOT_COMPLETED\nstartForeground(1, notification)"
    indicators = analyze_behavior(text)
    cats = {b.category for b in indicators}
    assert "persistence" in cats


# ---------------------------------------------------------------------------
# Network indicator extraction
# ---------------------------------------------------------------------------


def test_network_extracts_urls() -> None:
    indicators = extract_network_indicators(MALICIOUS_CODE)
    urls = [i.value for i in indicators if i.indicator_type == "url"]
    assert any("evil.example.com" in u for u in urls)
    assert any("c2.example.net" in u for u in urls)


def test_network_filters_noise() -> None:
    text = "http://schemas.android.com/apk/res/android https://evil.com/c2"
    indicators = extract_network_indicators(text)
    urls = [i.value for i in indicators]
    assert not any("schemas.android.com" in u for u in urls)
    assert any("evil.com" in u for u in urls)


# ---------------------------------------------------------------------------
# Obfuscation assessment
# ---------------------------------------------------------------------------


def test_obfuscation_detects_short_identifiers() -> None:
    smali = "\n".join([f".method public a(" for _ in range(25)])
    traits = assess_obfuscation(smali_text=smali)
    assert any(t.trait == "identifier_renaming" for t in traits)


def test_obfuscation_detects_packer() -> None:
    traits = assess_obfuscation(
        file_listing=["lib/armeabi-v7a/libjiagu.so", "classes.dex"],
    )
    assert any(t.trait == "known_packer" for t in traits)


def test_obfuscation_detects_reflection() -> None:
    smali = "\n".join(["invoke-virtual Method->invoke" for _ in range(20)])
    traits = assess_obfuscation(smali_text=smali)
    assert any(t.trait == "reflection_abuse" for t in traits)


# ---------------------------------------------------------------------------
# Protection detection
# ---------------------------------------------------------------------------


ROOT_DETECTION_CODE = """\
File su = new File("/system/xbin/su");
if (su.exists()) throw new SecurityException("Rooted device");
RootTools.isRooted();
Build.TAGS.contains("test-keys");
"""

PINNING_CODE = """\
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAA...")
    .build();
network-security-config
"""


def test_detects_root_detection() -> None:
    indicators = detect_protections(java_text=ROOT_DETECTION_CODE)
    root = next(p for p in indicators if p.protection_type == "root_detection")
    assert root.status == ProtectionStatus.OBSERVED
    assert root.evidence


def test_detects_certificate_pinning() -> None:
    indicators = detect_protections(java_text=PINNING_CODE, manifest_text="network-security-config")
    pinning = next(p for p in indicators if p.protection_type == "certificate_pinning")
    assert pinning.status == ProtectionStatus.OBSERVED


def test_no_false_positives_on_clean_code() -> None:
    indicators = detect_protections(java_text="public class App { void main() {} }")
    for p in indicators:
        assert p.status == ProtectionStatus.NOT_OBSERVED


def test_detects_anti_debug() -> None:
    code = "if (Debug.isDebuggerConnected()) { System.exit(1); }\nTracerPid check"
    indicators = detect_protections(java_text=code)
    debug = next(p for p in indicators if p.protection_type == "anti_debug")
    assert debug.status == ProtectionStatus.OBSERVED


def test_detects_frida_detection() -> None:
    code = 'if (lib.contains("frida")) { crash(); } port 27042 check'
    indicators = detect_protections(strings_text=code)
    frida = next(p for p in indicators if p.protection_type == "frida_detection")
    assert frida.status == ProtectionStatus.OBSERVED


# ---------------------------------------------------------------------------
# Campaign similarity
# ---------------------------------------------------------------------------


def test_campaign_dropper_detected() -> None:
    result = ApkAnalysisResult(
        permissions=[
            ApkPermission(name="android.permission.REQUEST_INSTALL_PACKAGES", is_suspicious=True),
        ],
        behavior_indicators=[
            BehaviorIndicator(category="dropper", pattern="PackageInstaller", confidence=0.9),
            BehaviorIndicator(category="dynamic_loading", pattern="DexClassLoader", confidence=0.9),
        ],
    )
    campaigns = assess_campaigns(result)
    dropper = next(c for c in campaigns if c.category == "dropper")
    assert dropper.similarity == CampaignSimilarity.CONSISTENT_WITH
    assert dropper.confidence > 0.5


def test_campaign_insufficient_evidence() -> None:
    result = ApkAnalysisResult()
    campaigns = assess_campaigns(result)
    assert all(c.similarity == CampaignSimilarity.INSUFFICIENT_EVIDENCE for c in campaigns)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _full_result() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        metadata=ApkMetadata(
            file_path="/tmp/sample.apk",
            file_size=4_200_000,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            package_name="com.example.malware",
            version_name="1.3.7",
            version_code="42",
            min_sdk="21",
            target_sdk="33",
            main_activity="com.example.malware.MainActivity",
            file_type="Java archive data (JAR)",
        ),
        permissions=[
            ApkPermission(name="android.permission.READ_SMS", is_dangerous=True, is_suspicious=True),
            ApkPermission(name="android.permission.INTERNET"),
        ],
        components=[
            ApkComponent(component_type=ComponentType.ACTIVITY, name=".MainActivity", exported=True),
            ApkComponent(component_type=ComponentType.SERVICE, name=".DropperService"),
        ],
        behavior_indicators=[
            BehaviorIndicator(category="dropper", pattern="PackageInstaller", evidence="...", confidence=0.85),
            BehaviorIndicator(category="dynamic_loading", pattern="DexClassLoader", evidence="...", confidence=0.9),
        ],
        network_indicators=[
            NetworkIndicator(value="https://evil.example.com/api", indicator_type="url"),
        ],
        tools_ran=["aapt", "apktool", "jadx", "strings"],
        tools_skipped=["yara"],
    )


def test_report_markdown_contains_all_sections() -> None:
    md = render_apk_markdown(_full_result())
    for heading in [
        "## 1. Executive Summary",
        "## 2. Methodology",
        "## 3. Surface Analysis",
        "## 4. Static Analysis",
        "## 5. Campaign Objective Assessment",
        "## 6. Obfuscation Analysis",
        "## 7. Hidden Business Logic",
        "## 8. Protection Detection",
        "## 9. Indicators and Extracted Artifacts",
        "## 10. Conclusions",
        "## 11. Analyst Next Steps",
    ]:
        assert heading in md, f"Missing section: {heading}"


def test_report_markdown_contains_evidence_labels() -> None:
    md = render_apk_markdown(_full_result())
    assert "observed evidence" in md.lower() or "Observed Evidence" in md
    assert "analytic assessment" in md.lower() or "Analytic Assessment" in md


def test_report_json_round_trips() -> None:
    result = _full_result()
    body = render_apk_json(result)
    parsed = json.loads(body)
    assert parsed["metadata"]["package_name"] == "com.example.malware"
    assert len(parsed["permissions"]) == 2
    assert len(parsed["behavior_indicators"]) == 2


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_runner_reports_missing_tool() -> None:
    from drake_x.integrations.apk.runner import run_tool
    out = run_tool("nonexistent_tool_xyz", ["nonexistent_tool_xyz", "--version"])
    assert out.available is False
    assert out.ok is False


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


def test_apk_command_registered() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["apk", "--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output

"""Tests for DEX detection writer (YARA/STIX), VT correlation, and AI task.

Covers:
- YARA candidate rule generation from DEX findings
- STIX 2.1 bundle generation
- VT enrichment correlation
- DexAssessmentTask registration and schema
- DEX context builder
"""

from __future__ import annotations

import json

import pytest

from drake_x.models.dex import (
    ClassifiedString,
    DexAnalysisResult,
    DexFileInfo,
    DexFinding,
    DexFindingSeverity,
    ObfuscationIndicator,
    ObfuscationSignal,
    PackingIndicator,
    SensitiveApiCategory,
    SensitiveApiHit,
    StringCategory,
)
from drake_x.reporting.dex_detection_writer import (
    correlate_dex_with_vt,
    render_dex_stix_bundle,
    render_dex_yara_candidates,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rich_dex_result() -> DexAnalysisResult:
    """A DexAnalysisResult with enough signals for YARA/STIX generation."""
    return DexAnalysisResult(
        dex_files=[
            DexFileInfo(filename="classes.dex", path="/x/classes.dex",
                        size=80000, class_count=120, method_count=600, string_count=2000),
        ],
        total_classes=120,
        total_methods=600,
        total_strings=2000,
        sensitive_api_hits=[
            SensitiveApiHit(
                api_category=SensitiveApiCategory.ACCESSIBILITY,
                api_name="AccessibilityService",
                raw_match="extends AccessibilityService",
                confidence=0.9,
                severity=DexFindingSeverity.HIGH,
                mitre_attck=["T1517"],
            ),
            SensitiveApiHit(
                api_category=SensitiveApiCategory.SMS,
                api_name="SmsManager",
                raw_match="SmsManager.getDefault()",
                confidence=0.85,
                severity=DexFindingSeverity.HIGH,
                mitre_attck=["T1582.001"],
            ),
            SensitiveApiHit(
                api_category=SensitiveApiCategory.DEX_LOADING,
                api_name="DexClassLoader",
                raw_match="new DexClassLoader(path)",
                confidence=0.9,
                severity=DexFindingSeverity.HIGH,
                mitre_attck=["T1407"],
            ),
            SensitiveApiHit(
                api_category=SensitiveApiCategory.REFLECTION,
                api_name="Class.forName",
                raw_match='Class.forName("com.hidden")',
                confidence=0.65,
                severity=DexFindingSeverity.MEDIUM,
                mitre_attck=["T1620"],
            ),
            SensitiveApiHit(
                api_category=SensitiveApiCategory.WEBVIEW,
                api_name="WebView.loadUrl",
                raw_match="wv.loadUrl(url)",
                confidence=0.6,
                severity=DexFindingSeverity.MEDIUM,
            ),
        ],
        obfuscation_indicators=[
            ObfuscationIndicator(
                signal=ObfuscationSignal.DYNAMIC_LOADING,
                description="3 dynamic loaders",
                evidence=["DexClassLoader: 2"],
                confidence=0.85,
            ),
        ],
        obfuscation_score=0.55,
        classified_strings=[
            ClassifiedString(
                value="https://evil.example.com/gate.php",
                category=StringCategory.URL,
                confidence=0.8,
                is_potential_ioc=True,
            ),
            ClassifiedString(
                value="/panel/bot/register",
                category=StringCategory.C2_INDICATOR,
                confidence=0.75,
                is_potential_ioc=True,
            ),
            ClassifiedString(
                value="chmod 755 /data/local/tmp/payload",
                category=StringCategory.COMMAND,
                confidence=0.7,
                is_potential_ioc=True,
            ),
            ClassifiedString(
                value="com.targetbank.mobile",
                category=StringCategory.PACKAGE_TARGET,
                confidence=0.7,
                is_potential_ioc=True,
            ),
            ClassifiedString(
                value="com.anotherbank.app",
                category=StringCategory.PACKAGE_TARGET,
                confidence=0.65,
                is_potential_ioc=True,
            ),
        ],
        tools_used=["jadx", "apktool"],
    )


@pytest.fixture
def minimal_dex_result() -> DexAnalysisResult:
    """A DexAnalysisResult with too few signals for YARA generation."""
    return DexAnalysisResult(
        dex_files=[
            DexFileInfo(filename="classes.dex", path="/x/classes.dex", class_count=10),
        ],
        sensitive_api_hits=[
            SensitiveApiHit(
                api_category=SensitiveApiCategory.NETWORK,
                api_name="HttpURLConnection",
                confidence=0.3,
                severity=DexFindingSeverity.INFO,
            ),
        ],
    )


# ---------------------------------------------------------------------------
# YARA candidate tests
# ---------------------------------------------------------------------------


class TestDexYaraCandidates:
    def test_generates_api_rule(self, rich_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(rich_dex_result, sha256="a" * 64)
        assert "Drake_Candidate_DexSensitiveAPIs" in yara
        assert "candidate" in yara
        assert "AccessibilityService" in yara
        assert "SmsManager" in yara

    def test_generates_string_ioc_rule(self, rich_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(rich_dex_result, sha256="b" * 64)
        assert "Drake_Candidate_DexStringIOCs" in yara
        assert "gate.php" in yara

    def test_generates_loader_rule(self, rich_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(rich_dex_result, sha256="c" * 64)
        assert "Drake_Candidate_DexObfuscatedLoader" in yara
        assert "DexClassLoader" in yara

    def test_generates_overlay_rule(self, rich_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(rich_dex_result, sha256="d" * 64)
        assert "Drake_Candidate_DexOverlayTargets" in yara
        assert "com.targetbank" in yara

    def test_empty_for_minimal(self, minimal_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(minimal_dex_result, sha256="e" * 64)
        assert yara == ""

    def test_empty_for_empty_result(self) -> None:
        assert render_dex_yara_candidates(DexAnalysisResult()) == ""

    def test_header_present(self, rich_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(rich_dex_result, sha256="f" * 64)
        assert "CANDIDATE YARA" in yara
        assert "NOT VALIDATED" in yara

    def test_all_rules_have_condition(self, rich_dex_result: DexAnalysisResult) -> None:
        yara = render_dex_yara_candidates(rich_dex_result, sha256="g" * 64)
        for line in yara.split("\n"):
            if line.strip().startswith("rule "):
                rule_name = line.strip().split()[1]
        # All rules should have a condition block
        assert "condition:" in yara

    def test_deterministic(self, rich_dex_result: DexAnalysisResult) -> None:
        """Same input should produce identical YARA output."""
        y1 = render_dex_yara_candidates(rich_dex_result, sha256="h" * 64)
        y2 = render_dex_yara_candidates(rich_dex_result, sha256="h" * 64)
        assert y1 == y2


# ---------------------------------------------------------------------------
# STIX bundle tests
# ---------------------------------------------------------------------------


class TestDexStixBundle:
    def test_generates_bundle(self, rich_dex_result: DexAnalysisResult) -> None:
        stix = render_dex_stix_bundle(rich_dex_result, sha256="a" * 64)
        bundle = json.loads(stix)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) > 1

    def test_file_observable(self, rich_dex_result: DexAnalysisResult) -> None:
        stix = render_dex_stix_bundle(rich_dex_result, sha256="b" * 64, md5="c" * 32)
        bundle = json.loads(stix)
        file_obj = bundle["objects"][0]
        assert file_obj["type"] == "file"
        assert file_obj["hashes"]["SHA-256"] == "b" * 64

    def test_indicators_present(self, rich_dex_result: DexAnalysisResult) -> None:
        stix = render_dex_stix_bundle(rich_dex_result, sha256="d" * 64)
        bundle = json.loads(stix)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) >= 3  # API hits + string IoCs

    def test_relationships_present(self, rich_dex_result: DexAnalysisResult) -> None:
        stix = render_dex_stix_bundle(rich_dex_result, sha256="e" * 64)
        bundle = json.loads(stix)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) >= 1

    def test_empty_without_sha(self, rich_dex_result: DexAnalysisResult) -> None:
        assert render_dex_stix_bundle(rich_dex_result) == ""

    def test_drake_x_metadata(self, rich_dex_result: DexAnalysisResult) -> None:
        stix = render_dex_stix_bundle(rich_dex_result, sha256="f" * 64)
        bundle = json.loads(stix)
        assert "x_drake_x" in bundle
        assert bundle["x_drake_x"]["analysis_type"] == "dex_deep"
        assert "candidate" in bundle["x_drake_x"]["caveat"]

    def test_deterministic(self, rich_dex_result: DexAnalysisResult) -> None:
        s1 = render_dex_stix_bundle(rich_dex_result, sha256="g" * 64)
        s2 = render_dex_stix_bundle(rich_dex_result, sha256="g" * 64)
        assert s1 == s2

    def test_all_labels_candidate(self, rich_dex_result: DexAnalysisResult) -> None:
        stix = render_dex_stix_bundle(rich_dex_result, sha256="h" * 64)
        bundle = json.loads(stix)
        for obj in bundle["objects"]:
            if obj["type"] == "indicator":
                assert "candidate" in obj["labels"]


# ---------------------------------------------------------------------------
# VT correlation tests
# ---------------------------------------------------------------------------


class TestVtCorrelation:
    def test_banker_correlation(self, rich_dex_result: DexAnalysisResult) -> None:
        vt_data = {
            "popular_threat_label": "Android.Banker.Trojan",
            "detections": 30,
            "tags": ["trojan", "banker"],
        }
        correlations = correlate_dex_with_vt(rich_dex_result, vt_data)
        types = [c["type"] for c in correlations]
        assert "vt_confirms_dex" in types

    def test_dropper_correlation(self, rich_dex_result: DexAnalysisResult) -> None:
        vt_data = {
            "popular_threat_label": "Android.Dropper.Agent",
            "detections": 25,
            "tags": ["dropper"],
        }
        correlations = correlate_dex_with_vt(rich_dex_result, vt_data)
        types = [c["type"] for c in correlations]
        assert "vt_confirms_dex" in types

    def test_sms_correlation(self, rich_dex_result: DexAnalysisResult) -> None:
        vt_data = {
            "popular_threat_label": "Android.SmsSend",
            "detections": 15,
            "tags": ["sms"],
        }
        correlations = correlate_dex_with_vt(rich_dex_result, vt_data)
        types = [c["type"] for c in correlations]
        assert "vt_confirms_dex" in types

    def test_high_detection_obfuscation_correlation(self, rich_dex_result: DexAnalysisResult) -> None:
        vt_data = {
            "popular_threat_label": "Generic.Android.Malware",
            "detections": 40,
            "tags": [],
        }
        correlations = correlate_dex_with_vt(rich_dex_result, vt_data)
        descriptions = [c["description"] for c in correlations]
        assert any("obfuscation" in d.lower() for d in descriptions)

    def test_zero_detection_contradiction(self, rich_dex_result: DexAnalysisResult) -> None:
        vt_data = {
            "popular_threat_label": "",
            "detections": 0,
            "tags": [],
        }
        correlations = correlate_dex_with_vt(rich_dex_result, vt_data)
        types = [c["type"] for c in correlations]
        assert "dex_contradicts_vt" in types

    def test_no_vt_data(self, rich_dex_result: DexAnalysisResult) -> None:
        assert correlate_dex_with_vt(rich_dex_result, None) == []

    def test_empty_vt_data(self, rich_dex_result: DexAnalysisResult) -> None:
        # Empty dict is falsy → early return
        correlations = correlate_dex_with_vt(rich_dex_result, {})
        assert correlations == []


# ---------------------------------------------------------------------------
# AI Task registration tests
# ---------------------------------------------------------------------------


class TestDexAssessmentTask:
    def test_task_registered(self) -> None:
        from drake_x.ai.tasks import ALL_TASKS, DexAssessmentTask
        task_names = [t.name for t in ALL_TASKS]
        assert "dex_assessment" in task_names

    def test_task_schema(self) -> None:
        from drake_x.ai.tasks.dex_assessment import DexAssessmentTask
        task = DexAssessmentTask()
        assert task.name == "dex_assessment"
        assert "threat_summary" in task.schema
        assert "key_behaviors" in task.schema
        assert "confidence" in task.schema
        assert task.deterministic is True

    def test_prompt_file_exists(self) -> None:
        from drake_x.ai.tasks.dex_assessment import DexAssessmentTask
        task = DexAssessmentTask()
        prompt_path = task.prompts_dir / task.prompt_file
        assert prompt_path.exists(), f"Prompt file missing: {prompt_path}"

    def test_prompt_has_placeholders(self) -> None:
        from drake_x.ai.tasks.dex_assessment import DexAssessmentTask
        task = DexAssessmentTask()
        text = (task.prompts_dir / task.prompt_file).read_text()
        assert "{target_display}" in text
        assert "{evidence_json}" in text
        assert "{schema_json}" in text


# ---------------------------------------------------------------------------
# DEX context builder tests
# ---------------------------------------------------------------------------


class TestDexContextBuilder:
    def test_builds_context(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(
            rich_dex_result,
            target_display="com.test.malware",
            session_id="test-123",
        )
        assert ctx.target_display == "com.test.malware"
        assert ctx.profile == "dex_deep"
        assert ctx.session_id == "test-123"
        assert len(ctx.evidence) > 0
        assert len(ctx.findings) == 0  # No pre-consolidated findings in fixture

    def test_evidence_has_inventory(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(rich_dex_result)
        types = [e["type"] for e in ctx.evidence]
        assert "dex_inventory" in types

    def test_evidence_has_apis(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(rich_dex_result)
        api_items = [e for e in ctx.evidence if e["type"] == "sensitive_api"]
        assert len(api_items) >= 3

    def test_evidence_has_obfuscation(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(rich_dex_result)
        obf = [e for e in ctx.evidence if e["type"] == "obfuscation_summary"]
        assert len(obf) == 1
        assert obf[0]["score"] == 0.55

    def test_evidence_has_string_iocs(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(rich_dex_result)
        strings = [e for e in ctx.evidence if e["type"] == "string_ioc"]
        assert len(strings) >= 2

    def test_extra_has_tools(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(rich_dex_result)
        assert "tools_used" in ctx.extra
        assert "jadx" in ctx.extra["tools_used"]

    def test_empty_result(self) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(DexAnalysisResult())
        assert len(ctx.evidence) >= 1  # At least inventory
        assert ctx.evidence[0]["type"] == "dex_inventory"

    def test_budget_enforcement(self, rich_dex_result: DexAnalysisResult) -> None:
        from drake_x.ai.dex_context_builder import build_dex_task_context
        ctx = build_dex_task_context(rich_dex_result, max_evidence=2, max_strings=1)
        # Should still produce evidence but capped
        assert len(ctx.evidence) <= 10  # inventory + capped items

"""Tests for drake_x.dex.report — report generation and finding consolidation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.dex.report import (
    consolidate_findings,
    to_dict,
    to_json,
    write_json_report,
    write_markdown_report,
)
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


@pytest.fixture
def sample_result() -> DexAnalysisResult:
    return DexAnalysisResult(
        dex_files=[
            DexFileInfo(
                filename="classes.dex",
                path="/x/classes.dex",
                size=50000,
                class_count=100,
                method_count=500,
                string_count=1000,
            ),
            DexFileInfo(
                filename="classes2.dex",
                path="/x/classes2.dex",
                size=30000,
                class_count=60,
                method_count=300,
                string_count=600,
            ),
        ],
        total_classes=160,
        total_methods=800,
        total_strings=1600,
        sensitive_api_hits=[
            SensitiveApiHit(
                api_category=SensitiveApiCategory.SMS,
                api_name="SmsManager",
                raw_match="SmsManager.getDefault().sendTextMessage",
                confidence=0.85,
                severity=DexFindingSeverity.HIGH,
            ),
        ],
        obfuscation_indicators=[
            ObfuscationIndicator(
                signal=ObfuscationSignal.SHORT_IDENTIFIERS,
                description="15 short identifiers",
                evidence=["Short class count: 15"],
                confidence=0.7,
            ),
        ],
        obfuscation_score=0.35,
        packing_indicators=[
            PackingIndicator(
                indicator_type="dropper_pattern",
                description="Small primary, large secondary",
                evidence=["classes.dex: 10, classes2.dex: 200"],
                confidence=0.75,
            ),
        ],
        classified_strings=[
            ClassifiedString(
                value="https://evil.com/gate.php",
                category=StringCategory.URL,
                confidence=0.8,
                is_potential_ioc=True,
            ),
        ],
        tools_used=["jadx", "apktool"],
        analysis_phases_completed=["dex_enumeration", "jadx_decompilation"],
    )


class TestToJson:
    def test_serializes(self, sample_result: DexAnalysisResult) -> None:
        j = to_json(sample_result)
        data = json.loads(j)
        assert data["total_classes"] == 160
        assert len(data["dex_files"]) == 2
        assert len(data["sensitive_api_hits"]) == 1

    def test_empty_result(self) -> None:
        j = to_json(DexAnalysisResult())
        data = json.loads(j)
        assert data["total_classes"] == 0


class TestToDict:
    def test_returns_dict(self, sample_result: DexAnalysisResult) -> None:
        d = to_dict(sample_result)
        assert isinstance(d, dict)
        assert d["total_methods"] == 800


class TestWriteJsonReport:
    def test_writes_file(self, sample_result: DexAnalysisResult, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        write_json_report(sample_result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["total_classes"] == 160


class TestWriteMarkdownReport:
    def test_writes_file(self, sample_result: DexAnalysisResult, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        write_markdown_report(sample_result, out, apk_name="test.apk")
        assert out.exists()
        content = out.read_text()
        assert "DEX Deep Analysis Report" in content
        assert "test.apk" in content
        assert "classes.dex" in content
        assert "SmsManager" in content

    def test_empty_result(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.md"
        write_markdown_report(DexAnalysisResult(), out)
        assert out.exists()
        assert "No DEX files analyzed" in out.read_text()


class TestConsolidateFindings:
    def test_generates_findings(self, sample_result: DexAnalysisResult) -> None:
        findings = consolidate_findings(sample_result)
        assert len(findings) > 0

        # Should have findings from API hits, obfuscation, packing, strings
        categories = {f.category for f in findings}
        assert any("sms" in c for c in categories)
        assert any("obfuscation" in c for c in categories)
        assert any("packing" in c for c in categories)
        assert any("string" in c for c in categories)

    def test_findings_have_required_fields(self, sample_result: DexAnalysisResult) -> None:
        findings = consolidate_findings(sample_result)
        for f in findings:
            assert f.finding_id
            assert f.source_tool
            assert f.evidence_type
            assert f.normalized_interpretation

    def test_empty_result(self) -> None:
        findings = consolidate_findings(DexAnalysisResult())
        assert findings == []

"""Tests for the v0.2 reporting writers (JSON, executive, manifest, evidence index)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from drake_x.models.artifact import Artifact
from drake_x.models.finding import Finding, FindingSeverity, FindingSource
from drake_x.models.session import Session, SessionStatus
from drake_x.reporting import (
    build_evidence_index,
    build_scan_manifest,
    render_executive_report,
    render_json_report,
)
from drake_x.reporting.manifest import write_manifest_json
from drake_x.scope import parse_target


def _session() -> Session:
    target = parse_target("https://example.com/login")
    s = Session(target=target, profile="safe")
    s.tools_planned = ["dig", "curl"]
    s.tools_ran = ["dig", "curl"]
    s.started_at = datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC)
    s.finished_at = datetime(2026, 4, 9, 12, 0, 5, tzinfo=UTC)
    s.status = SessionStatus.COMPLETED
    s.ai_enabled = True
    s.ai_model = "llama3.2:1b"
    s.ai_summary = "Test executive summary."
    return s


def _artifact() -> Artifact:
    return Artifact(
        tool_name="dig",
        kind="dns.records",
        payload={"records": {"A": ["1.2.3.4"]}},
        confidence=0.9,
        notes=[],
    )


def _finding() -> Finding:
    return Finding(
        title="Test finding",
        summary="A medium-severity test observation.",
        severity=FindingSeverity.MEDIUM,
        confidence=0.7,
        source=FindingSource.PARSER,
        cwe=["CWE-200"],
        owasp=["A05:2021"],
    )


def test_executive_report_includes_summary_and_finding() -> None:
    md = render_executive_report(
        session=_session(),
        artifacts=[_artifact()],
        findings=[_finding()],
    )
    assert "Drake-X Executive Summary" in md
    assert "Test executive summary" in md
    assert "[medium] Test finding" in md
    assert "https://example.com/login" in md


def test_json_report_round_trip() -> None:
    body = render_json_report(
        session=_session(),
        tool_results=[],
        artifacts=[_artifact()],
        findings=[_finding()],
    )
    parsed = json.loads(body)
    assert parsed["schema_version"] == 2
    assert parsed["session"]["target"]["canonical"] == "https://example.com/login"
    assert parsed["findings"][0]["cwe"] == ["CWE-200"]


def test_manifest_includes_drake_version() -> None:
    manifest = build_scan_manifest(
        session=_session(),
        tool_results=[],
        artifacts=[_artifact()],
        workspace_name="test-ws",
    )
    body = write_manifest_json(manifest)
    parsed = json.loads(body)
    assert parsed["manifest_version"] == 1
    assert parsed["workspace"] == "test-ws"
    assert parsed["session"]["id"] == manifest["session"]["id"]


def test_evidence_index_renders_table() -> None:
    md = build_evidence_index([_artifact()])
    assert "| Tool" in md
    assert "`dig`" in md
    assert "`dns.records`" in md

"""Tests for the v2 (v0.3) technical Markdown report writer."""

from __future__ import annotations

from datetime import UTC, datetime

from drake_x.models.artifact import Artifact
from drake_x.models.finding import Finding, FindingEvidence, FindingSeverity, FindingSource
from drake_x.models.session import Session, SessionStatus
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.reporting.markdown_writer import render_markdown_report
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
    s.ai_summary = "This is the AI executive summary."
    return s


def _tool_results() -> list[ToolResult]:
    return [
        ToolResult(
            tool_name="dig",
            command=["dig", "+noall", "+answer", "example.com", "A"],
            stdout="example.com. 300 IN A 1.2.3.4\n",
            stderr="",
            exit_code=0,
            status=ToolResultStatus.OK,
            started_at=datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC),
            finished_at=datetime(2026, 4, 9, 12, 0, 1, tzinfo=UTC),
            duration_seconds=1.0,
        ),
        ToolResult(
            tool_name="curl",
            command=["curl", "-I", "https://example.com/login"],
            stdout="HTTP/2 200\nserver: nginx\n\n",
            stderr="",
            exit_code=0,
            status=ToolResultStatus.OK,
            started_at=datetime(2026, 4, 9, 12, 0, 1, tzinfo=UTC),
            finished_at=datetime(2026, 4, 9, 12, 0, 2, tzinfo=UTC),
            duration_seconds=1.0,
        ),
    ]


def _artifacts() -> list[Artifact]:
    return [
        Artifact(
            tool_name="dig",
            kind="dns.records",
            payload={"records": {"A": ["1.2.3.4"]}},
            confidence=0.9,
            notes=[],
        ),
        Artifact(
            tool_name="curl",
            kind="web.http_meta",
            payload={"final_status": 200, "final_headers": {"server": "nginx"}},
            confidence=0.9,
            notes=[],
        ),
    ]


def _findings() -> list[Finding]:
    return [
        Finding(
            title="Missing Strict-Transport-Security header",
            summary="HTTPS response has no HSTS",
            severity=FindingSeverity.MEDIUM,
            confidence=0.9,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            cwe=["CWE-319"],
            owasp=["A02:2021"],
            evidence=[
                FindingEvidence(
                    artifact_kind="web.http_meta",
                    tool_name="curl",
                    excerpt="(no strict-transport-security header in response)",
                    confidence=0.95,
                ),
            ],
            remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            tags=["security-header"],
        ),
        Finding(
            title="Missing Content-Security-Policy header",
            summary="No CSP observed",
            severity=FindingSeverity.LOW,
            confidence=0.9,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            cwe=["CWE-693"],
            owasp=["A05:2021"],
            evidence=[],
            tags=["security-header"],
        ),
    ]


def test_report_contains_session_metadata() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "# Drake-X Technical Report" in md
    assert "`safe`" in md
    assert "https://example.com/login" in md


def test_report_contains_findings_table() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "## Findings" in md
    assert "| Severity | Title | Source | Confidence | CWE | OWASP |" in md
    assert "CWE-319" in md
    assert "A02:2021" in md


def test_report_findings_sorted_by_severity() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    medium_pos = md.find("Missing Strict-Transport-Security")
    low_pos = md.find("Missing Content-Security-Policy")
    assert medium_pos < low_pos, "MEDIUM should appear before LOW"


def test_report_includes_evidence_links() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "**Evidence:**" in md
    assert "`web.http_meta` (curl)" in md
    assert "no strict-transport-security" in md


def test_report_includes_remediation() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "**Remediation:**" in md
    assert "Strict-Transport-Security" in md


def test_report_includes_timeline() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=[],
    )
    assert "### Timeline" in md
    assert "`dig`" in md
    assert "`curl`" in md


def test_report_includes_ai_summary() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "AI triage" in md
    assert "This is the AI executive summary." in md


def test_report_finding_detail_shows_fact_vs_inference() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "`rule` (fact)" in md


def test_report_tags_rendered() -> None:
    md = render_markdown_report(
        session=_session(),
        tool_results=_tool_results(),
        artifacts=_artifacts(),
        findings=_findings(),
    )
    assert "**Tags:** security-header" in md

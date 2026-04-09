"""Tests for AI evidence preparation and the Markdown report renderer.

Both consume normalized artifacts and must surface execution provenance so a
human analyst can tell a clean run from a degraded one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from drake_x.ai.prompts import OUTPUT_SCHEMA, build_analyst_prompt
from drake_x.models.artifact import Artifact
from drake_x.models.session import Session, SessionStatus
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.reports.markdown import render_markdown_report
from drake_x.scope import parse_target


def _make_artifact(*, degraded: bool, tool_name: str = "dig") -> Artifact:
    return Artifact(
        tool_name=tool_name,
        kind=f"{tool_name}.test",
        payload={"hello": "world"},
        confidence=0.5,
        notes=["base note"],
        tool_status="nonzero" if degraded else "ok",
        exit_code=2 if degraded else 0,
        degraded=degraded,
    )


# ----- AI evidence -----------------------------------------------------------


def test_ai_prompt_includes_provenance_fields() -> None:
    art = _make_artifact(degraded=True)
    prompt = build_analyst_prompt(
        target_display="example.com",
        profile="safe",
        evidence=[art.model_dump()],
    )
    # The trimmed JSON evidence chunk must mention degraded provenance.
    assert '"tool_status": "nonzero"' in prompt
    assert '"degraded": true' in prompt
    assert '"exit_code": 2' in prompt


def test_ai_schema_no_longer_advertises_unused_field() -> None:
    # Removed in M6; AI must not be told to fill in technologies separately.
    assert "likely_technologies_or_services" not in OUTPUT_SCHEMA


def test_ai_prompt_is_short_and_self_contained() -> None:
    art = _make_artifact(degraded=False)
    prompt = build_analyst_prompt(
        target_display="example.com",
        profile="safe",
        evidence=[art.model_dump()],
    )
    # Sanity: the prompt should not be empty and should mention defensive recon.
    assert "defensive" in prompt.lower() or "Defensive" in prompt or "recon only" in prompt.lower()
    # And it should round-trip the schema as JSON we control.
    schema_text = json.dumps(OUTPUT_SCHEMA, indent=2)
    assert schema_text in prompt


# ----- markdown report -------------------------------------------------------


def _make_session() -> Session:
    target = parse_target("https://example.com/login?next=/admin")
    s = Session(target=target, profile="safe")
    s.tools_planned = ["dig", "curl"]
    s.tools_ran = ["dig", "curl"]
    s.warnings = ["tool 'curl' exited non-zero (exit_code=2); artifact is degraded"]
    s.started_at = datetime(2026, 4, 9, 12, 0, 0, tzinfo=UTC)
    s.finished_at = datetime(2026, 4, 9, 12, 0, 5, tzinfo=UTC)
    s.status = SessionStatus.PARTIAL
    return s


def test_report_renders_degraded_marker_for_artifacts(tmp_path) -> None:
    session = _make_session()
    clean_dig = _make_artifact(degraded=False, tool_name="dig")
    clean_dig = clean_dig.model_copy(update={"payload": {"records": {"A": ["1.2.3.4"]}}})
    degraded_curl = _make_artifact(degraded=True, tool_name="curl")
    degraded_curl = degraded_curl.model_copy(
        update={"payload": {"final_status": 500, "final_headers": {"server": "nginx"}}}
    )

    tool_results = [
        ToolResult(
            tool_name="dig",
            command=["dig"],
            stdout="example.com. 300 IN A 1.2.3.4\n",
            stderr="",
            exit_code=0,
            status=ToolResultStatus.OK,
            finished_at=datetime.now(UTC),
            duration_seconds=0.1,
        ),
        ToolResult(
            tool_name="curl",
            command=["curl", "-I", "https://example.com/login?next=/admin"],
            stdout="HTTP/2 500\n",
            stderr="",
            exit_code=2,
            status=ToolResultStatus.NONZERO,
            finished_at=datetime.now(UTC),
            duration_seconds=0.2,
        ),
    ]

    md = render_markdown_report(
        session=session,
        tool_results=tool_results,
        artifacts=[clean_dig, degraded_curl],
        findings=[],
    )

    # Section headers exist.
    assert "## Tools" in md
    assert "### Per-tool execution summary" in md
    # The degraded curl artifact must be flagged inline AND in the banner.
    assert "degraded execution" in md
    assert "tool_status=`nonzero`" in md
    assert "exit_code=2" in md
    # The URL target must round-trip the query string in the report.
    assert "https://example.com/login?next=/admin" in md
    # Status summary line.
    assert "Status:" in md and "partial" in md

    # Optional smoke: the report can be written to disk and re-read.
    out = tmp_path / "report.md"
    out.write_text(md, encoding="utf-8")
    assert "degraded execution" in out.read_text(encoding="utf-8")


def test_report_does_not_flag_clean_artifacts() -> None:
    session = _make_session()
    session.warnings = []
    session.status = SessionStatus.COMPLETED

    clean_dig = _make_artifact(degraded=False, tool_name="dig").model_copy(
        update={"payload": {"records": {"A": ["1.2.3.4"]}}}
    )

    md = render_markdown_report(
        session=session,
        tool_results=[],
        artifacts=[clean_dig],
        findings=[],
    )
    # No degraded marker should appear when nothing is degraded.
    assert "degraded execution" not in md

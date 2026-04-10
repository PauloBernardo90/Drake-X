"""Tests for v0.6: drake status, assist audit logging, mission templates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from drake_x.cli import app
from drake_x.core.storage import WorkspaceStorage
from drake_x.core.workspace import Workspace
from drake_x.models.finding import Finding, FindingSeverity, FindingSource
from drake_x.models.session import Session
from drake_x.scope import parse_target

runner = CliRunner()

_SCOPE_YAML = """\
engagement: test
authorization_reference: "TEST-V06"
allow_active: false
in_scope:
  - kind: domain
    value: example.com
out_of_scope:
  - kind: domain
    value: nope.test
"""


def _init_workspace(tmp_path: Path, name: str = "v06") -> Workspace:
    ws = Workspace.init(name, root=tmp_path)
    ws.scope_path.write_text(_SCOPE_YAML, encoding="utf-8")
    return ws


# ======================================================================
# drake status
# ======================================================================


def test_status_command_registered() -> None:
    result = runner.invoke(app, ["status", "--help"])
    assert result.exit_code == 0


def test_status_empty_workspace(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    result = runner.invoke(app, ["status", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "Workspace" in result.output
    assert "Scope" in result.output
    assert "Sessions" in result.output
    assert "no sessions" in result.output.lower()


def test_status_populated_workspace(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    session = Session(target=parse_target("example.com"), profile="safe")
    storage.legacy.save_session(session)
    storage.save_finding(session.id, Finding(
        title="Test", summary="test", severity=FindingSeverity.MEDIUM,
        source=FindingSource.RULE,
    ))
    result = runner.invoke(app, ["status", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "total:" in result.output.lower()
    assert "medium" in result.output.lower()


def test_status_shows_tool_availability(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    result = runner.invoke(app, ["status", "-w", str(ws.root)])
    assert "Tools" in result.output
    # At least one tool category should be shown
    assert "available" in result.output.lower() or "missing" in result.output.lower()


def test_status_missing_graph_degrades_gracefully(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    result = runner.invoke(app, ["status", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "no evidence graph" in result.output.lower()


# ======================================================================
# assist audit logging
# ======================================================================


def test_assist_session_storage_round_trip(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    storage = WorkspaceStorage(ws.db_path)

    storage.create_assist_session("a-123", "v06", "web", "example.com", "2026-01-01T00:00:00Z")
    storage.log_assist_event("a-123", "2026-01-01T00:01:00Z", 1,
                             json.dumps({"suggested_action": "run recon_passive"}),
                             "approve", "drake recon run example.com", "success")
    storage.log_assist_event("a-123", "2026-01-01T00:02:00Z", 2,
                             json.dumps({"suggested_action": "run headers_audit"}),
                             "reject")
    storage.end_assist_session("a-123", "2026-01-01T00:03:00Z")

    events = storage.load_assist_events("a-123")
    assert len(events) == 2
    assert events[0]["operator_action"] == "approve"
    assert events[1]["operator_action"] == "reject"

    sessions = storage.list_assist_sessions()
    assert len(sessions) >= 1
    assert sessions[0]["ended_at"] is not None


def test_assist_partial_session(tmp_path: Path) -> None:
    """An interrupted session (no end) should still have events."""
    ws = _init_workspace(tmp_path)
    storage = WorkspaceStorage(ws.db_path)

    storage.create_assist_session("a-456", "v06", "recon", "example.com", "2026-01-01T00:00:00Z")
    storage.log_assist_event("a-456", "2026-01-01T00:01:00Z", 1,
                             json.dumps({"error": "ai failed"}), "ai_failed")
    # No end_assist_session call

    events = storage.load_assist_events("a-456")
    assert len(events) == 1
    sessions = storage.list_assist_sessions()
    partial = next(s for s in sessions if s["id"] == "a-456")
    assert partial["ended_at"] is None


def test_assist_history_command(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    storage.create_assist_session("a-789", "v06", "web", "example.com", "2026-01-01T00:00:00Z")
    storage.log_assist_event("a-789", "2026-01-01T00:01:00Z", 1,
                             json.dumps({"suggested_action": "run recon_passive"}),
                             "approve", "drake recon run", "success")
    result = runner.invoke(app, ["assist", "history", "a-789", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "step 1" in result.output
    assert "approve" in result.output


def test_assist_export_command(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    storage.create_assist_session("a-exp", "v06", "web", "example.com", "2026-01-01T00:00:00Z")
    storage.log_assist_event("a-exp", "2026-01-01T00:01:00Z", 1,
                             json.dumps({"suggested_action": "test"}), "approve")
    result = runner.invoke(app, ["assist", "export", "a-exp", "-w", str(ws.root)])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "assist_session" in parsed
    assert "events" in parsed
    assert len(parsed["events"]) == 1


# ======================================================================
# mission templates
# ======================================================================


def test_mission_list_shows_builtins(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    result = runner.invoke(app, ["mission", "list", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "recon" in result.output
    assert "web" in result.output
    assert "full" in result.output


def test_mission_show_builtin() -> None:
    result = runner.invoke(app, ["mission", "show", "recon"])
    assert result.exit_code == 0
    assert "recon_passive" in result.output
    assert "recon_active" in result.output


def test_mission_template_loads_from_workspace(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    missions_dir = ws.root / "missions"
    missions_dir.mkdir(exist_ok=True)
    (missions_dir / "custom-audit.toml").write_text("""\
name = "custom-audit"

[[steps]]
label = "Passive"
module = "recon_passive"

[[steps]]
label = "Headers"
module = "headers_audit"

[[steps]]
label = "Active"
module = "recon_active"
skippable = true
""", encoding="utf-8")

    result = runner.invoke(app, ["mission", "show", "custom-audit", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "recon_passive" in result.output
    assert "headers_audit" in result.output


def test_mission_template_listed(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    missions_dir = ws.root / "missions"
    missions_dir.mkdir(exist_ok=True)
    (missions_dir / "my-mission.toml").write_text("""\
[[steps]]
module = "recon_passive"
label = "Passive"
""", encoding="utf-8")

    result = runner.invoke(app, ["mission", "list", "-w", str(ws.root)])
    assert result.exit_code == 0
    assert "my-mission" in result.output


def test_mission_invalid_template_rejected(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    result = runner.invoke(app, [
        "mission", "run", "nonexistent-mission", "example.com",
        "-w", str(ws.root), "--dry-run", "--yes",
    ])
    assert result.exit_code != 0


def test_mission_template_dry_run(tmp_path: Path) -> None:
    ws = _init_workspace(tmp_path)
    missions_dir = ws.root / "missions"
    missions_dir.mkdir(exist_ok=True)
    (missions_dir / "test-dry.toml").write_text("""\
[[steps]]
module = "recon_passive"
label = "Passive"
""", encoding="utf-8")

    result = runner.invoke(app, [
        "mission", "run", "test-dry", "example.com",
        "-w", str(ws.root), "--dry-run", "--yes",
    ])
    assert result.exit_code == 0
    assert "Mission complete" in result.output


def test_mission_template_scope_enforcement(tmp_path: Path) -> None:
    """Templates must still enforce scope."""
    ws = _init_workspace(tmp_path)
    missions_dir = ws.root / "missions"
    missions_dir.mkdir(exist_ok=True)
    (missions_dir / "scoped.toml").write_text("""\
[[steps]]
module = "recon_passive"
label = "Passive"
""", encoding="utf-8")

    result = runner.invoke(app, [
        "mission", "run", "scoped", "evil.test",
        "-w", str(ws.root), "--dry-run", "--yes",
    ])
    # evil.test is not in scope — should fail
    assert "denied" in result.output.lower() or "out of scope" in result.output.lower() or result.exit_code != 0


# ======================================================================
# compatibility
# ======================================================================


def test_all_commands_present() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["status", "mission", "assist", "flow", "init", "scope",
                "recon", "web", "api", "apk", "graph", "findings", "ai",
                "report", "tools"]:
        assert cmd in result.output, f"{cmd} missing"

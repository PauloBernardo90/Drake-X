"""Tests for the v0.5.1 UX layer: Mission CLI, Assist Mode, Flow navigation."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from drake_x.ai.ollama_client import OllamaClient
from drake_x.ai.tasks import AssistSuggestTask
from drake_x.cli import app


runner = CliRunner()


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def test_mission_command_registered() -> None:
    result = runner.invoke(app, ["mission", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output


def test_assist_command_registered() -> None:
    result = runner.invoke(app, ["assist", "--help"])
    assert result.exit_code == 0
    assert "start" in result.output


def test_flow_command_registered() -> None:
    result = runner.invoke(app, ["flow", "--help"])
    assert result.exit_code == 0
    assert "navigation" in result.output.lower() or "menu" in result.output.lower() or "Flow" in result.output


# ---------------------------------------------------------------------------
# Mission CLI
# ---------------------------------------------------------------------------


def test_mission_rejects_unknown_type() -> None:
    result = runner.invoke(app, ["mission", "run", "banana", "example.com"])
    assert result.exit_code != 0


def test_mission_dry_run_no_crash(tmp_path: Path) -> None:
    """A dry-run mission against a workspace should plan but not execute."""
    from drake_x.core.workspace import Workspace
    from drake_x.safety.scope_file import write_scope_template, load_scope_file

    ws = Workspace.init("mission-test", root=tmp_path)
    # Write a scope that allows example.com.
    scope_content = """
engagement: test
authorization_reference: "TEST"
allow_active: false
in_scope:
  - kind: domain
    value: example.com
out_of_scope:
  - kind: domain
    value: do-not-scan.test
"""
    ws.scope_path.write_text(scope_content, encoding="utf-8")

    result = runner.invoke(app, [
        "mission", "run", "recon", "example.com",
        "-w", str(ws.root),
        "--dry-run", "--yes",
    ])
    # Should not crash — dry-run plans without executing.
    assert result.exit_code == 0
    assert "Mission complete" in result.output or "dry" in result.output.lower()


def test_mission_no_active_skips_active_steps(tmp_path: Path) -> None:
    from drake_x.core.workspace import Workspace

    ws = Workspace.init("mission-noactive", root=tmp_path)
    scope_content = """
engagement: test
authorization_reference: "TEST"
allow_active: false
in_scope:
  - kind: domain
    value: example.com
out_of_scope:
  - kind: domain
    value: do-not-scan.test
"""
    ws.scope_path.write_text(scope_content, encoding="utf-8")

    result = runner.invoke(app, [
        "mission", "run", "web", "example.com",
        "-w", str(ws.root),
        "--no-active", "--dry-run", "--yes",
    ])
    assert result.exit_code == 0
    assert "skipped" in result.output.lower()


def test_mission_scope_enforcement(tmp_path: Path) -> None:
    """A mission against an out-of-scope target must be refused."""
    from drake_x.core.workspace import Workspace

    ws = Workspace.init("mission-scope", root=tmp_path)
    scope_content = """
engagement: test
authorization_reference: "TEST"
allow_active: false
in_scope:
  - kind: domain
    value: allowed.example
out_of_scope:
  - kind: domain
    value: do-not-scan.test
"""
    ws.scope_path.write_text(scope_content, encoding="utf-8")

    result = runner.invoke(app, [
        "mission", "run", "recon", "evil.test",
        "-w", str(ws.root),
        "--dry-run", "--yes",
    ])
    # Should fail because evil.test is not in scope.
    assert "out of scope" in result.output.lower() or "denied" in result.output.lower() or result.exit_code != 0


# ---------------------------------------------------------------------------
# Assist Mode
# ---------------------------------------------------------------------------


def test_assist_suggest_task_has_prompt() -> None:
    task = AssistSuggestTask()
    path = task.prompts_dir / task.prompt_file
    assert path.exists()


def test_assist_suggest_task_schema() -> None:
    assert "suggested_action" in AssistSuggestTask.schema
    assert "module" in AssistSuggestTask.schema
    assert "reason" in AssistSuggestTask.schema


def test_assist_requires_ollama() -> None:
    """Assist mode must fail gracefully when Ollama is unreachable."""
    from drake_x.core.workspace import Workspace

    # We don't set up a real workspace here — just check that the
    # command fails with a clear error rather than a traceback.
    result = runner.invoke(app, [
        "assist", "start", "web", "example.com",
    ])
    # Without a workspace or Ollama, it should exit with an error.
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Flow navigation
# ---------------------------------------------------------------------------


def test_flow_exits_on_q() -> None:
    result = runner.invoke(app, ["flow"], input="q\n")
    assert result.exit_code == 0
    assert "ended" in result.output.lower() or "exit" in result.output.lower()


def test_flow_shows_menu() -> None:
    result = runner.invoke(app, ["flow"], input="q\n")
    assert "Recon" in result.output or "recon" in result.output.lower()


def test_flow_handles_valid_selection() -> None:
    result = runner.invoke(app, ["flow"], input="1\nq\n")
    assert result.exit_code == 0
    # Should show the command for selection 1 (Workspace Setup).
    assert "drake" in result.output.lower()


def test_flow_handles_invalid_selection() -> None:
    result = runner.invoke(app, ["flow"], input="99\nq\n")
    assert result.exit_code == 0
    assert "invalid" in result.output.lower()


# ---------------------------------------------------------------------------
# All existing commands still work
# ---------------------------------------------------------------------------


def test_all_original_commands_still_present() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["init", "scope", "recon", "web", "api", "apk", "graph",
                "findings", "ai", "report", "tools",
                "mission", "assist", "flow"]:
        assert cmd in result.output, f"{cmd} missing from help output"

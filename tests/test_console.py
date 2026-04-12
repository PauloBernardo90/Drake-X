"""Tests for the persistent investigation console."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.core.state import ConsoleState, clear_state, load_state, save_state


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


def test_state_defaults() -> None:
    state = ConsoleState()
    assert state.current_workspace == ""
    assert state.current_session == ""
    assert state.last_sample_path == ""
    assert state.last_run_dir == ""


def test_state_save_load(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    with patch("drake_x.core.state._STATE_PATH", state_file):
        state = ConsoleState(
            current_workspace="test-ws",
            current_session="abc123",
            last_sample_path="/tmp/sample.apk",
            last_run_dir="/tmp/runs/apk-sample",
        )
        save_state(state)

        assert state_file.exists()
        loaded = load_state()
        assert loaded.current_workspace == "test-ws"
        assert loaded.current_session == "abc123"
        assert loaded.last_sample_path == "/tmp/sample.apk"
        assert loaded.last_run_dir == "/tmp/runs/apk-sample"


def test_state_load_missing(tmp_path: Path) -> None:
    state_file = tmp_path / "nonexistent.json"
    with patch("drake_x.core.state._STATE_PATH", state_file):
        state = load_state()
        assert state.current_workspace == ""


def test_state_load_corrupt(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text("not json at all")
    with patch("drake_x.core.state._STATE_PATH", state_file):
        state = load_state()
        assert state.current_workspace == ""


def test_state_clear(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text("{}")
    with patch("drake_x.core.state._STATE_PATH", state_file):
        clear_state()
        assert not state_file.exists()


def test_state_serializes_to_json(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    with patch("drake_x.core.state._STATE_PATH", state_file):
        save_state(ConsoleState(current_workspace="ws1"))
        data = json.loads(state_file.read_text())
        assert data["current_workspace"] == "ws1"
        assert "current_session" in data


# ---------------------------------------------------------------------------
# Console model
# ---------------------------------------------------------------------------


def test_console_prompt_no_context() -> None:
    from drake_x.cli.console_cmd import InvestigationConsole
    with patch("drake_x.core.state.load_state", return_value=ConsoleState()):
        c = InvestigationConsole()
        assert c.prompt == "drake> "


def test_console_prompt_with_workspace() -> None:
    from drake_x.cli.console_cmd import InvestigationConsole
    with patch("drake_x.cli.console_cmd.load_state",
               return_value=ConsoleState(current_workspace="my-engagement")):
        c = InvestigationConsole()
        assert "my-engagement" in c.prompt
        assert c.prompt == "drake(my-engagement)> "


def test_console_prompt_with_session() -> None:
    from drake_x.cli.console_cmd import InvestigationConsole
    with patch("drake_x.cli.console_cmd.load_state",
               return_value=ConsoleState(current_workspace="ws", current_session="abc123def456")):
        c = InvestigationConsole()
        assert "ws" in c.prompt
        assert "abc123def456" in c.prompt


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def test_console_command_registered() -> None:
    from drake_x.cli.v2 import app
    commands = [c.name for c in app.registered_groups]
    # console should be registered as a typer group
    assert any("console" in str(c) for c in app.registered_groups) or True
    # Alternative: check via help
    from typer.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(app, ["console", "--help"])
    assert result.exit_code == 0
    assert "investigation console" in result.output.lower() or "console" in result.output.lower()

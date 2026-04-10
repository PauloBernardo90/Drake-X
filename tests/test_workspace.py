"""Workspace init/load tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.core.workspace import Workspace
from drake_x.exceptions import WorkspaceError


def test_init_creates_layout(tmp_path: Path) -> None:
    ws = Workspace.init("acme", root=tmp_path, operator="alice")
    assert ws.root == (tmp_path / "acme").resolve()
    assert ws.config_path.exists()
    assert ws.scope_path.exists()
    assert ws.runs_dir.exists()
    assert ws.audit_log_path.exists()
    assert ws.config.name == "acme"
    assert ws.config.operator == "alice"


def test_init_refuses_non_empty_workspace(tmp_path: Path) -> None:
    (tmp_path / "acme").mkdir()
    (tmp_path / "acme" / "stale.txt").write_text("hi", encoding="utf-8")
    with pytest.raises(WorkspaceError):
        Workspace.init("acme", root=tmp_path)


def test_init_force_allows_reuse(tmp_path: Path) -> None:
    (tmp_path / "acme").mkdir()
    (tmp_path / "acme" / "stale.txt").write_text("hi", encoding="utf-8")
    ws = Workspace.init("acme", root=tmp_path, force=True)
    assert ws.config_path.exists()


def test_load_round_trip(tmp_path: Path) -> None:
    Workspace.init("acme", root=tmp_path, operator="bob")
    loaded = Workspace.load(str(tmp_path / "acme"))
    assert loaded.name == "acme"
    assert loaded.config.operator == "bob"
    assert loaded.scope_path.exists()


def test_load_missing_workspace_raises(tmp_path: Path) -> None:
    with pytest.raises(WorkspaceError):
        Workspace.load(str(tmp_path / "nope"))

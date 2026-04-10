"""End-to-end tests for the v0.2 engine.

These tests exercise the engine + workspace + scope enforcer + storage,
mocking subprocess execution exactly the way the v1 orchestrator tests do.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.core.engine import Engine
from drake_x.core.plugin_loader import PluginLoader
from drake_x.core.storage import WorkspaceStorage
from drake_x.core.workspace import Workspace
from drake_x.exceptions import OutOfScopeError
from drake_x.models.scope import ScopeAsset, ScopeFile
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.safety.confirm import ConfirmGate, ConfirmMode
from drake_x.scope import parse_target


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    return Workspace.init("test-engagement", root=tmp_path)


@pytest.fixture
def in_scope() -> ScopeFile:
    return ScopeFile(
        engagement="test",
        authorization_reference="TEST-1",
        in_scope=[ScopeAsset(kind="wildcard_domain", value="example.com")],
        out_of_scope=[],
        allow_active=True,  # let active modules through for these tests
    )


@pytest.fixture
def all_tools_present():
    with patch("drake_x.tools.base.shutil.which", return_value="/usr/bin/fake"):
        yield


def _ok_result(name: str, stdout: str = "fake-output") -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name, "fake"],
        stdout=stdout,
        stderr="",
        exit_code=0,
        status=ToolResultStatus.OK,
        finished_at=datetime.now(UTC),
        duration_seconds=0.05,
    )


def _patched_run(name_to_result):
    async def _run(self, target, *, timeout=None):  # noqa: ARG001
        result = name_to_result.get(self.meta.name)
        if result is None:
            return ToolResult(
                tool_name=self.meta.name,
                command=[self.meta.binary],
                status=ToolResultStatus.NOT_INSTALLED,
                error_message="not installed (mock default)",
                finished_at=datetime.now(UTC),
                duration_seconds=0.0,
            )
        return result

    return _run


def test_engine_dry_run_writes_audit_no_tools(workspace: Workspace, in_scope: ScopeFile) -> None:
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()
    engine = Engine(
        workspace=workspace,
        scope=in_scope,
        loader=loader,
        storage=storage,
        confirm=ConfirmGate(mode=ConfirmMode.YES),
    )
    target = parse_target("example.com")
    plan = engine.plan(target=target, profile="passive")
    report = asyncio.run(engine.run(plan, dry_run=True))
    assert report.session.warnings
    assert "dry-run" in " ".join(report.session.warnings)
    # Audit log should have at least one entry.
    assert workspace.audit_log_path.exists()
    text = workspace.audit_log_path.read_text(encoding="utf-8")
    assert "plan" in text
    assert "dry_run" in text


def test_engine_refuses_out_of_scope_target(workspace: Workspace, in_scope: ScopeFile) -> None:
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()
    engine = Engine(
        workspace=workspace,
        scope=in_scope,
        loader=loader,
        storage=storage,
        confirm=ConfirmGate(mode=ConfirmMode.YES),
    )
    target = parse_target("not-example.test")
    with pytest.raises(OutOfScopeError):
        engine.plan(target=target, profile="passive")
    # The denial must be recorded in the audit log.
    text = workspace.audit_log_path.read_text(encoding="utf-8")
    assert "deny" in text


def test_engine_full_run_persists_results(
    workspace: Workspace, in_scope: ScopeFile, all_tools_present
) -> None:
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()

    fake_results = {
        "dig": _ok_result("dig", "example.com.\t300\tIN\tA\t1.2.3.4\n"),
        "whois": _ok_result(
            "whois",
            "Registrar: TestRegistrar\nName Server: ns1.example.com\n",
        ),
        "curl": _ok_result(
            "curl",
            "HTTP/1.1 200 OK\nserver: nginx\ncontent-type: text/html\n\n",
        ),
    }

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        engine = Engine(
            workspace=workspace,
            scope=in_scope,
            loader=loader,
            storage=storage,
            confirm=ConfirmGate(mode=ConfirmMode.YES),
        )
        target = parse_target("example.com")
        plan = engine.plan(target=target, profile="passive")
        report = asyncio.run(engine.run(plan))

    assert report.session.id
    assert "dig" in report.session.tools_ran
    assert "whois" in report.session.tools_ran
    assert any(a.tool_name == "dig" for a in report.artifacts)

    # Scope snapshot must round-trip.
    in_assets, out_assets = storage.load_scope_snapshot(report.session.id)
    assert any(a.kind == "wildcard_domain" and a.value == "example.com" for a in in_assets)


def test_engine_active_blocked_without_allow_active(
    workspace: Workspace, all_tools_present
) -> None:
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()
    scope = ScopeFile(
        engagement="t",
        authorization_reference="X",
        in_scope=[ScopeAsset(kind="wildcard_domain", value="example.com")],
        out_of_scope=[],
        allow_active=False,
    )
    engine = Engine(
        workspace=workspace,
        scope=scope,
        loader=loader,
        storage=storage,
        confirm=ConfirmGate(mode=ConfirmMode.YES),
    )
    target = parse_target("example.com")
    plan = engine.plan(target=target, profile="safe")
    # nmap and whatweb should be denied by policy.
    denied_names = {n.name for n, _ in plan.denied_by_policy}
    assert "nmap" in denied_names
    assert "whatweb" in denied_names
    # dig and whois should still be runnable.
    runnable_names = {e.name for e in plan.eligible}
    assert "dig" in runnable_names
    assert "whois" in runnable_names

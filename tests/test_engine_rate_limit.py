"""Tests for the v0.3 rate-limiter wiring in the engine."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.core.engine import Engine
from drake_x.core.plugin_loader import PluginLoader
from drake_x.core.rate_limit import RateLimiter
from drake_x.core.storage import WorkspaceStorage
from drake_x.core.workspace import Workspace
from drake_x.integrations.optional.httpx import HttpxTool
from drake_x.models.scope import ScopeAsset, ScopeFile
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.safety.confirm import ConfirmGate, ConfirmMode
from drake_x.scope import parse_target
from drake_x.tools.curl import CurlTool
from drake_x.tools.dig import DigTool
from drake_x.tools.nikto import NiktoTool
from drake_x.tools.nmap import NmapTool
from drake_x.tools.whatweb import WhatWebTool
from drake_x.tools.whois import WhoisTool


# ----- meta flag --------------------------------------------------------------


def test_http_style_flag_set_on_http_tools() -> None:
    assert CurlTool.meta.http_style is True
    assert WhatWebTool.meta.http_style is True
    assert NiktoTool.meta.http_style is True
    assert HttpxTool.meta.http_style is True


def test_http_style_flag_unset_on_non_http_tools() -> None:
    assert NmapTool.meta.http_style is False
    assert DigTool.meta.http_style is False
    assert WhoisTool.meta.http_style is False


# ----- recording rate limiter -------------------------------------------------


class _RecordingLimiter:
    """Drop-in stand-in for RateLimiter that just records every acquire."""

    def __init__(self) -> None:
        self.acquired_for: list[str] = []
        self.released = 0

    async def acquire(self, host: str) -> None:
        self.acquired_for.append(host)

    def release(self) -> None:
        self.released += 1

    def slot(self, host: str) -> "_Slot":
        return _Slot(self, host)


class _Slot:
    def __init__(self, lim: _RecordingLimiter, host: str) -> None:
        self._lim = lim
        self._host = host

    async def __aenter__(self) -> None:
        await self._lim.acquire(self._host)

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._lim.release()


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    return Workspace.init("rl-test", root=tmp_path)


@pytest.fixture
def in_scope() -> ScopeFile:
    return ScopeFile(
        engagement="t",
        authorization_reference="RL-1",
        in_scope=[ScopeAsset(kind="wildcard_domain", value="example.com")],
        out_of_scope=[],
        allow_active=True,
    )


@pytest.fixture
def all_tools_present():
    with patch("drake_x.tools.base.shutil.which", return_value="/usr/bin/fake"):
        yield


def _ok_result(name: str, stdout: str = "ok") -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name, "fake"],
        stdout=stdout,
        stderr="",
        exit_code=0,
        status=ToolResultStatus.OK,
        finished_at=datetime.now(UTC),
        duration_seconds=0.01,
    )


def _patched_run(name_to_result):
    async def _run(self, target, *, timeout=None):  # noqa: ARG001
        result = name_to_result.get(self.meta.name)
        if result is None:
            return ToolResult(
                tool_name=self.meta.name,
                command=[self.meta.binary],
                status=ToolResultStatus.NOT_INSTALLED,
                error_message="not installed (mock)",
                finished_at=datetime.now(UTC),
                duration_seconds=0.0,
            )
        return result

    return _run


# ----- engine integration tests ----------------------------------------------


def test_engine_rate_limits_only_http_style_tools(
    workspace, in_scope, all_tools_present
) -> None:
    """Passive run hits dig + whois + curl. Only curl must go through the limiter."""
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()
    recorder = _RecordingLimiter()

    fake_results = {
        "dig": _ok_result("dig", "example.com.\t300\tIN\tA\t1.2.3.4\n"),
        "whois": _ok_result("whois", "Registrar: x\n"),
        "curl": _ok_result("curl", "HTTP/1.1 200 OK\nserver: nginx\n\n"),
    }

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        engine = Engine(
            workspace=workspace,
            scope=in_scope,
            loader=loader,
            storage=storage,
            confirm=ConfirmGate(mode=ConfirmMode.YES),
            rate_limiter=recorder,
        )
        target = parse_target("example.com")
        plan = engine.plan(target=target, profile="passive")
        asyncio.run(engine.run(plan))

    # Only curl should have acquired a rate-limit slot.
    assert recorder.acquired_for == ["example.com"]
    assert recorder.released == 1


def test_engine_default_rate_limiter_is_built_from_scope(workspace, in_scope) -> None:
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()
    engine = Engine(
        workspace=workspace,
        scope=in_scope,
        loader=loader,
        storage=storage,
    )
    assert isinstance(engine.rate_limiter, RateLimiter)
    # The default scope fixture uses the model defaults: 4 / 5.0
    assert engine.rate_limiter._global._value == in_scope.max_concurrency
    assert pytest.approx(1.0 / engine.rate_limiter._min_interval, rel=0.01) == in_scope.rate_limit_per_host_rps


def test_engine_acquire_each_http_call(workspace, in_scope, all_tools_present) -> None:
    """A safe-profile run hits dig + whois + curl + whatweb + httpx + sslscan + nmap.

    Three of those are http_style (curl, whatweb, httpx) — the rest must
    bypass the limiter entirely.
    """
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()
    recorder = _RecordingLimiter()

    fake_results = {
        "dig": _ok_result("dig", "example.com.\t300\tIN\tA\t1.2.3.4\n"),
        "whois": _ok_result("whois", "Registrar: x\n"),
        "curl": _ok_result("curl", "HTTP/1.1 200 OK\nserver: nginx\n\n"),
        "whatweb": _ok_result("whatweb", '{"target":"http://example.com","plugins":{"nginx":{}}}'),
        "httpx": _ok_result("httpx", '{"url":"https://example.com","status_code":200,"header":{"server":"nginx"}}'),
        "sslscan": _ok_result("sslscan", "  TLSv1.2   enabled\nSubject: example.com\n"),
        "nmap": _ok_result(
            "nmap",
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="1.2.3.4" addrtype="ipv4"/>'
            '<status state="up"/><hostnames/></host></nmaprun>',
        ),
    }

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        engine = Engine(
            workspace=workspace,
            scope=in_scope,
            loader=loader,
            storage=storage,
            confirm=ConfirmGate(mode=ConfirmMode.YES),
            rate_limiter=recorder,
        )
        target = parse_target("example.com")
        plan = engine.plan(target=target, profile="safe")
        asyncio.run(engine.run(plan))

    # Three HTTP-style integrations in the safe profile (curl + whatweb + httpx)
    # all targeting the same host → three identical slot acquires.
    assert sorted(recorder.acquired_for) == [
        "example.com",
        "example.com",
        "example.com",
    ]
    assert recorder.released == 3


# ----- direct rate limiter timing tests --------------------------------------


def test_rate_limiter_global_concurrency_caps_parallelism() -> None:
    """With max_concurrency=1, two acquires must serialize even on different hosts."""
    rl = RateLimiter(max_concurrency=1, per_host_rps=1000.0)
    timeline: list[tuple[str, float]] = []

    async def worker(host: str, label: str) -> None:
        async with rl.slot(host):
            timeline.append(("start", time.monotonic()))
            await asyncio.sleep(0.05)
            timeline.append(("stop", time.monotonic()))

    asyncio.run(_gather_two(rl, worker))

    # The order must be start/stop/start/stop (no interleaving).
    kinds = [t[0] for t in timeline]
    assert kinds == ["start", "stop", "start", "stop"]


def test_rate_limiter_per_host_pacing_introduces_gap() -> None:
    """Two acquires for the same host must be at least 1/rps seconds apart."""
    rps = 5.0  # 200ms gap minimum
    rl = RateLimiter(max_concurrency=10, per_host_rps=rps)

    async def driver() -> list[float]:
        timestamps: list[float] = []

        async def hit() -> None:
            async with rl.slot("example.com"):
                timestamps.append(time.monotonic())

        await hit()
        await hit()
        return timestamps

    timestamps = asyncio.run(driver())
    gap = timestamps[1] - timestamps[0]
    assert gap >= (1.0 / rps) * 0.8, f"expected >=160ms gap, got {gap*1000:.0f}ms"


async def _gather_two(rl, worker):
    a = asyncio.create_task(worker("a.example", "A"))
    b = asyncio.create_task(worker("b.example", "B"))
    await asyncio.gather(a, b)

"""Orchestrator behavior tests with mocked subprocess execution."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.ai.analyzer import AIAnalyzer
from drake_x.ai.ollama_client import OllamaClient
from drake_x.config import DEFAULT_CONFIG
from drake_x.constants import PROFILE_PASSIVE, PROFILE_SAFE
from drake_x.exceptions import AIUnavailableError
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.orchestrator import Orchestrator
from drake_x.registry import ToolRegistry
from drake_x.scope import parse_target
from drake_x.session_store import SessionStore


@pytest.fixture
def tmp_store(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "drake.db")


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
    """Build an async drop-in for ``BaseTool.run`` keyed on tool name."""

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


def test_run_scan_persists_session_and_results(tmp_store, all_tools_present) -> None:
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path, default_timeout=5)
    registry = ToolRegistry(default_timeout=5)

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
        "whatweb": _ok_result(
            "whatweb",
            '{"target":"http://example.com","plugins":{"nginx":{}}}',
        ),
        "sslscan": _ok_result(
            "sslscan",
            "  TLSv1.2   enabled\n  TLSv1.3   enabled\nSubject: example.com\n",
        ),
    }

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_SAFE, ai_enabled=False))

    assert report.session.id
    assert "dig" in report.session.tools_ran
    assert "whois" in report.session.tools_ran
    assert "curl" in report.session.tools_ran
    assert report.session.status.value in {"completed", "partial"}
    assert len(report.tool_results) >= 3
    assert any(a.tool_name == "dig" for a in report.artifacts)

    # Persisted state should round-trip.
    loaded = tmp_store.load_session(report.session.id)
    assert loaded is not None
    assert loaded.target.canonical == "example.com"
    assert tmp_store.load_tool_results(report.session.id)
    assert tmp_store.load_artifacts(report.session.id)


def test_run_scan_with_no_tools_installed_records_warnings(tmp_store) -> None:
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path)
    registry = ToolRegistry(default_timeout=5)

    with patch("drake_x.tools.base.shutil.which", return_value=None):
        registry.refresh_availability()
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_SAFE, ai_enabled=False))

    assert report.session.tools_ran == []
    assert report.session.tools_skipped  # something skipped
    assert any("no eligible tools" in w or "skipped" in w for w in report.session.warnings)


def test_run_scan_handles_timeout(tmp_store, all_tools_present) -> None:
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path, default_timeout=5)
    registry = ToolRegistry(default_timeout=5)

    def _timeout_for(name: str) -> ToolResult:
        return ToolResult(
            tool_name=name,
            command=[name],
            status=ToolResultStatus.TIMEOUT,
            error_message="timed out",
            finished_at=datetime.now(UTC),
            duration_seconds=5.0,
        )

    fake_results = {
        "dig": _timeout_for("dig"),
        "whois": _ok_result("whois", "Registrar: r\n"),
        "curl": _ok_result("curl", "HTTP/1.1 200 OK\n\n"),
    }

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_PASSIVE, ai_enabled=False))

    assert any("timed out" in w for w in report.session.warnings)
    assert report.session.status.value == "partial"


def test_run_scan_with_unreachable_ai(tmp_store, all_tools_present) -> None:
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path)
    registry = ToolRegistry(default_timeout=5)

    fake_results = {
        "dig": _ok_result("dig", "example.com. 300 IN A 1.2.3.4\n"),
        "whois": _ok_result("whois", "Registrar: x\n"),
    }

    class _BoomClient(OllamaClient):
        def __init__(self) -> None:
            super().__init__(base_url="http://localhost:65530", model="fake")

        async def is_available(self) -> bool:
            return True  # pretend reachable, then explode

        async def generate(self, prompt: str, *, system: str | None = None) -> str:
            raise AIUnavailableError("boom")

    ai = AIAnalyzer(client=_BoomClient())

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=ai)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_PASSIVE, ai_enabled=True))

    # AI failure must NOT raise — orchestrator absorbs it as a warning.
    assert any("AI" in w for w in report.session.warnings)
    assert report.session.ai_summary is None


def test_ollama_client_is_available_returns_false_when_unreachable() -> None:
    client = OllamaClient(base_url="http://127.0.0.1:1", model="fake")
    assert asyncio.run(client.is_available()) is False


# ----- exception safety -----------------------------------------------------


def _exploding_run(boom_tool: str):
    """Drop-in for ``BaseTool.run`` that raises for one tool and is OK for the rest."""

    async def _run(self, target, *, timeout=None):  # noqa: ARG001
        if self.meta.name == boom_tool:
            raise RuntimeError(f"simulated wrapper bug in {boom_tool}")
        return ToolResult(
            tool_name=self.meta.name,
            command=[self.meta.binary],
            stdout="",
            stderr="",
            exit_code=0,
            status=ToolResultStatus.OK,
            finished_at=datetime.now(UTC),
            duration_seconds=0.01,
        )

    return _run


def test_serial_tool_exception_does_not_crash_scan(tmp_store, all_tools_present) -> None:
    """nmap is the serial tool in the safe profile (parallel_safe=False).

    A bug in its wrapper must become an ERROR result, not a top-level crash.
    """
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path, default_timeout=5)
    registry = ToolRegistry(default_timeout=5)

    with patch("drake_x.tools.base.BaseTool.run", new=_exploding_run("nmap")):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_SAFE, ai_enabled=False))

    nmap_result = next(r for r in report.tool_results if r.tool_name == "nmap")
    assert nmap_result.status == ToolResultStatus.ERROR
    assert "wrapper exception" in (nmap_result.error_message or "")
    # Other tools must have produced a clean result.
    assert any(r.tool_name == "dig" and r.status == ToolResultStatus.OK for r in report.tool_results)
    assert report.session.status.value == "partial"
    assert any("nmap" in w for w in report.session.warnings)


def test_parallel_tool_exception_does_not_kill_peers(tmp_store, all_tools_present) -> None:
    """A wrapper that raises in the parallel batch must not lose peer results."""
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path, default_timeout=5)
    registry = ToolRegistry(default_timeout=5)

    # `dig` is parallel-safe in the passive profile.
    with patch("drake_x.tools.base.BaseTool.run", new=_exploding_run("dig")):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_PASSIVE, ai_enabled=False))

    dig_result = next(r for r in report.tool_results if r.tool_name == "dig")
    assert dig_result.status == ToolResultStatus.ERROR
    # Peer parallel tools must still have produced clean results.
    other_oks = [r for r in report.tool_results if r.tool_name != "dig" and r.status == ToolResultStatus.OK]
    assert other_oks, "expected at least one peer tool to complete OK"
    assert report.session.status.value == "partial"


def test_nonzero_tool_marks_session_partial_and_warns(tmp_store, all_tools_present) -> None:
    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path, default_timeout=5)
    registry = ToolRegistry(default_timeout=5)

    def _nonzero(name: str, stdout: str = "") -> ToolResult:
        return ToolResult(
            tool_name=name,
            command=[name],
            stdout=stdout,
            stderr="boom",
            exit_code=2,
            status=ToolResultStatus.NONZERO,
            finished_at=datetime.now(UTC),
            duration_seconds=0.05,
        )

    fake_results = {
        "dig": _nonzero(
            "dig",
            "example.com.\t300\tIN\tA\t1.2.3.4\n",
        ),
        "whois": _ok_result("whois", "Registrar: r\n"),
        "curl": _ok_result("curl", "HTTP/1.1 200 OK\nserver: nginx\n\n"),
    }

    with patch("drake_x.tools.base.BaseTool.run", new=_patched_run(fake_results)):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_PASSIVE, ai_enabled=False))

    # Session is partial and has an explicit nonzero warning.
    assert report.session.status.value == "partial"
    assert any("non-zero" in w and "dig" in w for w in report.session.warnings)
    # `dig` is still considered as having ran (it executed).
    assert "dig" in report.session.tools_ran
    # The dig artifact carries provenance.
    dig_art = next(a for a in report.artifacts if a.tool_name == "dig")
    assert dig_art.degraded is True
    assert dig_art.tool_status == "nonzero"
    assert dig_art.exit_code == 2

    # And the persisted artifact must round-trip the provenance.
    loaded = tmp_store.load_artifacts(report.session.id)
    loaded_dig = next(a for a in loaded if a.tool_name == "dig")
    assert loaded_dig.degraded is True
    assert loaded_dig.tool_status == "nonzero"
    assert loaded_dig.exit_code == 2


def test_parallel_gather_with_leaked_exception_is_recovered(tmp_store, all_tools_present) -> None:
    """Bypass _run_one's safety net to confirm _run_parallel's belt-and-braces
    handling also works when an exception leaks all the way up to gather."""

    target = parse_target("example.com")
    config = DEFAULT_CONFIG.with_overrides(db_path=tmp_store.db_path, default_timeout=5)
    registry = ToolRegistry(default_timeout=5)

    async def boom(self, entry, target, timeout):  # noqa: ARG001
        if entry.name == "dig":
            raise RuntimeError("leaked")
        return ToolResult(
            tool_name=entry.name,
            command=[entry.binary],
            exit_code=0,
            status=ToolResultStatus.OK,
            finished_at=datetime.now(UTC),
            duration_seconds=0.0,
        )

    with patch("drake_x.orchestrator.Orchestrator._run_one", new=boom):
        orch = Orchestrator(config=config, registry=registry, store=tmp_store, ai=None)
        report = asyncio.run(orch.run_scan(target, profile=PROFILE_PASSIVE, ai_enabled=False))

    dig_result = next(r for r in report.tool_results if r.tool_name == "dig")
    assert dig_result.status == ToolResultStatus.ERROR
    assert "wrapper exception" in (dig_result.error_message or "")

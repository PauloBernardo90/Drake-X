"""Tests for the subfinder integration: build_command, normalizer, plugin discovery.

subfinder graduated from stub to a real :class:`BaseTool` in this cycle.
These tests cover the release-gate surface: command construction, the
normalizer (including defensive parsing), dispatch routing, plugin
loader discovery, and the passive action policy classification.
"""

from __future__ import annotations

from datetime import UTC, datetime

from drake_x.core.plugin_loader import PluginLoader
from drake_x.integrations.optional import OPTIONAL_REAL_TOOLS, OPTIONAL_STUBS
from drake_x.integrations.optional.subfinder import SubfinderStub, SubfinderTool
from drake_x.models.scope import ScopeAsset, ScopeFile
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.normalize import normalize_result
from drake_x.normalize.subfinder import normalize_subfinder
from drake_x.safety.policy import ActionPolicy, PolicyClassifier
from drake_x.scope import parse_target


# ----- build_command --------------------------------------------------------


def test_subfinder_build_command_uses_silent_and_domain_flag() -> None:
    tool = SubfinderTool(default_timeout=60)
    cmd = tool.build_command(parse_target("example.com"))
    assert cmd[0] == "subfinder"
    assert "-silent" in cmd
    assert "-no-color" in cmd
    idx = cmd.index("-d")
    assert cmd[idx + 1] == "example.com"


def test_subfinder_meta_is_passive_and_domain_only() -> None:
    assert "passive" in SubfinderTool.meta.profiles
    assert "safe" in SubfinderTool.meta.profiles
    assert SubfinderTool.meta.target_types == ("domain",)
    assert SubfinderTool.meta.parallel_safe is True
    # passive integration — must NOT opt into the HTTP rate limiter.
    assert SubfinderTool.meta.http_style is False


def test_subfinder_stub_alias_is_the_real_tool() -> None:
    """Backwards-compat alias must point at the same class so older imports keep working."""
    assert SubfinderStub is SubfinderTool


# ----- normalizer -----------------------------------------------------------


def _result(stdout: str, *, exit_code: int = 0, host: str = "example.com") -> ToolResult:
    return ToolResult(
        tool_name="subfinder",
        command=["subfinder", "-silent", "-no-color", "-d", host],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        status=ToolResultStatus.OK if exit_code == 0 else ToolResultStatus.NONZERO,
        finished_at=datetime.now(UTC),
        duration_seconds=0.5,
    )


def test_normalize_subfinder_parses_plain_list() -> None:
    stdout = "a.example.com\nb.example.com\nwww.example.com\n"
    art = normalize_subfinder(_result(stdout))
    assert art.tool_name == "subfinder"
    assert art.kind == "dns.subdomains"
    assert art.confidence >= 0.85
    assert art.payload["count"] == 3
    assert art.payload["root"] == "example.com"
    assert art.payload["subdomains"] == [
        "a.example.com",
        "b.example.com",
        "www.example.com",
    ]


def test_normalize_subfinder_deduplicates_and_lowercases() -> None:
    stdout = "A.Example.com\na.example.com\nB.EXAMPLE.COM\n"
    art = normalize_subfinder(_result(stdout))
    assert art.payload["subdomains"] == ["a.example.com", "b.example.com"]
    assert art.payload["count"] == 2


def test_normalize_subfinder_drops_out_of_root_rows() -> None:
    stdout = "good.example.com\nevil.attacker.test\nother.example.com\n"
    art = normalize_subfinder(_result(stdout))
    assert art.payload["subdomains"] == ["good.example.com", "other.example.com"]
    assert any("discarded" in n for n in art.notes)


def test_normalize_subfinder_drops_malformed_rows() -> None:
    stdout = "ok.example.com\nnot a domain\n..bad..\n"
    art = normalize_subfinder(_result(stdout))
    assert art.payload["subdomains"] == ["ok.example.com"]
    assert any("discarded" in n for n in art.notes)


def test_normalize_subfinder_empty_output() -> None:
    art = normalize_subfinder(_result(""))
    assert art.confidence == 0.0
    assert art.payload["count"] == 0
    assert "empty subfinder output" in art.notes[0]


def test_normalize_subfinder_unparseable_output() -> None:
    art = normalize_subfinder(_result("totally\nnot\ndomains\n"))
    assert art.payload["count"] == 0
    assert art.confidence <= 0.3


def test_normalize_dispatch_routes_subfinder() -> None:
    art = normalize_result(_result("a.example.com\nb.example.com\n"))
    assert art is not None
    assert art.kind == "dns.subdomains"
    assert art.payload["count"] == 2


# ----- plugin loader discovery ---------------------------------------------


def test_plugin_loader_discovers_subfinder_as_optional_real() -> None:
    loader = PluginLoader(default_timeout=60).load()
    entry = loader.get("subfinder")
    assert entry is not None
    assert entry.cls is SubfinderTool
    assert entry.origin == "optional"
    assert entry.binary == "subfinder"


def test_subfinder_is_in_optional_real_tools_not_stubs() -> None:
    assert SubfinderTool in OPTIONAL_REAL_TOOLS
    assert all(cls is not SubfinderTool for cls in OPTIONAL_STUBS)


# ----- safety / policy -----------------------------------------------------


def test_subfinder_policy_classification_is_passive() -> None:
    scope = ScopeFile(
        engagement="test",
        authorization_reference="TEST-1",
        in_scope=[ScopeAsset(kind="domain", value="example.com")],
        out_of_scope=[],
    )
    classifier = PolicyClassifier(scope)
    decision = classifier.decide("subfinder")
    assert decision.policy == ActionPolicy.PASSIVE
    assert decision.allowed is True
    assert decision.requires_confirmation is False


# ----- not-installed behavior ----------------------------------------------


def test_subfinder_returns_not_installed_when_binary_missing(monkeypatch) -> None:
    """When the binary is absent, BaseTool.run must return a NOT_INSTALLED result."""
    import asyncio

    import drake_x.tools.base as base_mod

    monkeypatch.setattr(base_mod.shutil, "which", lambda _name: None)
    tool = SubfinderTool(default_timeout=30)
    result = asyncio.run(tool.run(parse_target("example.com"), timeout=5))
    assert result.status == ToolResultStatus.NOT_INSTALLED
    assert "subfinder" in (result.error_message or "").lower()

"""Tests for the v0.3 httpx integration: build_command, normalizer, plugin discovery."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from drake_x.core.plugin_loader import PluginLoader
from drake_x.integrations.optional.httpx import HttpxStub, HttpxTool
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.normalize import normalize_result
from drake_x.normalize.httpx import normalize_httpx
from drake_x.scope import parse_target


# ----- build_command --------------------------------------------------------


def test_httpx_build_command_for_url_preserves_scheme_and_path() -> None:
    tool = HttpxTool(default_timeout=30)
    cmd = tool.build_command(parse_target("https://example.com/login?next=/admin"))
    assert cmd[0] == "httpx"
    assert "-json" in cmd
    assert "-include-response-header" in cmd
    assert "-silent" in cmd
    assert "-follow-redirects" in cmd
    assert cmd[-2] == "-u"
    assert cmd[-1] == "https://example.com/login?next=/admin"


def test_httpx_build_command_for_domain_defaults_to_https() -> None:
    tool = HttpxTool(default_timeout=30)
    cmd = tool.build_command(parse_target("example.com"))
    assert cmd[-2] == "-u"
    assert cmd[-1] == "https://example.com"


def test_httpx_meta_is_http_style_and_lives_in_safe_profile() -> None:
    assert HttpxTool.meta.http_style is True
    assert "safe" in HttpxTool.meta.profiles
    # Deliberately NOT in passive — httpx makes a real GET request.
    assert "passive" not in HttpxTool.meta.profiles


def test_httpx_stub_alias_is_the_real_tool() -> None:
    """Backwards-compat alias must point at the same class so old code paths work."""
    assert HttpxStub is HttpxTool


# ----- normalizer -----------------------------------------------------------


def _result(stdout: str, exit_code: int = 0) -> ToolResult:
    return ToolResult(
        tool_name="httpx",
        command=["httpx", "-json", "-u", "https://example.com"],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        status=ToolResultStatus.OK if exit_code == 0 else ToolResultStatus.NONZERO,
        finished_at=datetime.now(UTC),
        duration_seconds=0.1,
    )


def _httpx_record() -> dict:
    return {
        "timestamp": "2026-04-10T09:12:33Z",
        "url": "https://example.com",
        "input": "https://example.com",
        "host": "93.184.216.34",
        "scheme": "https",
        "port": "443",
        "method": "GET",
        "status_code": 200,
        "title": "Example Domain",
        "webserver": "ECS (dcb/7F84)",
        "content_type": "text/html",
        "content_length": 1256,
        "tech": ["ECS (dcb/7F84)"],
        "a": ["93.184.216.34"],
        "cnames": [],
        "chain_status_codes": [200],
        "header": {
            "Server": "ECS (dcb/7F84)",
            "Content-Type": "text/html",
            "Content-Length": "1256",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        },
    }


def test_normalize_httpx_parses_jsonl_record() -> None:
    art = normalize_httpx(_result(json.dumps(_httpx_record())))
    assert art.tool_name == "httpx"
    assert art.kind == "web.http_probe"
    assert art.confidence >= 0.85
    assert art.payload["status_code"] == 200
    assert art.payload["title"] == "Example Domain"
    assert art.payload["scheme"] == "https"
    assert art.payload["port"] == 443
    assert art.payload["technologies"] == ["ECS (dcb/7F84)"]
    assert "strict-transport-security" in art.payload["headers"]
    assert art.payload["headers"]["server"] == "ECS (dcb/7F84)"


def test_normalize_httpx_handles_legacy_headers_key() -> None:
    record = _httpx_record()
    record["headers"] = record.pop("header")
    art = normalize_httpx(_result(json.dumps(record)))
    assert "server" in art.payload["headers"]


def test_normalize_httpx_handles_list_valued_headers() -> None:
    record = _httpx_record()
    record["header"] = {"Set-Cookie": ["a=1; Path=/", "b=2; Path=/"]}
    art = normalize_httpx(_result(json.dumps(record)))
    assert "set-cookie" in art.payload["headers"]
    assert "a=1" in art.payload["headers"]["set-cookie"]
    assert "b=2" in art.payload["headers"]["set-cookie"]


def test_normalize_httpx_empty_output() -> None:
    art = normalize_httpx(_result(""))
    assert art.confidence == 0.0
    assert "empty httpx output" in art.notes[0]


def test_normalize_httpx_garbage_output() -> None:
    art = normalize_httpx(_result("not json at all\n{not really json either"))
    assert art.confidence == 0.0
    assert any("no JSON object" in n for n in art.notes)
    assert art.raw_stdout_excerpt is not None


def test_normalize_dispatch_routes_httpx() -> None:
    """The common dispatcher must route httpx tool results to the new normalizer."""
    art = normalize_result(_result(json.dumps(_httpx_record())))
    assert art is not None
    assert art.kind == "web.http_probe"
    assert art.payload["status_code"] == 200


# ----- plugin loader discovery ----------------------------------------------


def test_plugin_loader_discovers_httpx() -> None:
    loader = PluginLoader(default_timeout=30).load()
    entry = loader.get("httpx")
    assert entry is not None
    assert entry.cls is HttpxTool
    assert entry.origin == "optional"
    # Whether `installed` is True depends on the host; both are valid.
    assert entry.binary == "httpx"

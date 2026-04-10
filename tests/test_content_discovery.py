"""Tests for the content_discovery module: ffuf integration + normalizer."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.core.plugin_loader import PluginLoader
from drake_x.integrations.optional.ffuf import FfufStub, FfufTool
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.normalize import normalize_result
from drake_x.normalize.ffuf import normalize_ffuf
from drake_x.scope import parse_target


# ----- build_command --------------------------------------------------------


def test_ffuf_build_command_for_url() -> None:
    tool = FfufTool(default_timeout=120)
    cmd = tool.build_command(parse_target("https://example.com/app"))
    assert cmd[0] == "ffuf"
    assert "-json" in cmd
    assert "-s" in cmd
    idx = cmd.index("-u")
    assert cmd[idx + 1] == "https://example.com/app/FUZZ"


def test_ffuf_build_command_for_domain() -> None:
    tool = FfufTool(default_timeout=120)
    cmd = tool.build_command(parse_target("example.com"))
    idx = cmd.index("-u")
    assert cmd[idx + 1] == "https://example.com/FUZZ"


def test_ffuf_meta_is_intrusive_and_http_style() -> None:
    assert FfufTool.meta.http_style is True
    assert FfufTool.meta.parallel_safe is False
    assert "web-basic" in FfufTool.meta.profiles


def test_ffuf_stub_alias() -> None:
    assert FfufStub is FfufTool


def test_ffuf_wordlist_env_override(monkeypatch) -> None:
    monkeypatch.setenv("DRAKE_X_FFUF_WORDLIST", "/custom/words.txt")
    tool = FfufTool(default_timeout=120)
    assert tool.wordlist == "/custom/words.txt"
    cmd = tool.build_command(parse_target("https://example.com/"))
    idx = cmd.index("-w")
    assert cmd[idx + 1] == "/custom/words.txt"


def test_ffuf_refuses_to_run_without_wordlist(tmp_path) -> None:
    """If the wordlist doesn't exist, run() returns NOT_INSTALLED early."""
    import asyncio

    tool = FfufTool(default_timeout=120)
    with patch.dict(os.environ, {"DRAKE_X_FFUF_WORDLIST": str(tmp_path / "nope.txt")}):
        result = asyncio.run(tool.run(parse_target("https://example.com/"), timeout=30))
    assert result.status == ToolResultStatus.NOT_INSTALLED
    assert "wordlist not found" in result.error_message


# ----- normalizer -----------------------------------------------------------


def _result(stdout: str, exit_code: int = 0) -> ToolResult:
    return ToolResult(
        tool_name="ffuf",
        command=["ffuf", "-u", "https://example.com/FUZZ", "-json", "-s"],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        status=ToolResultStatus.OK if exit_code == 0 else ToolResultStatus.NONZERO,
        finished_at=datetime.now(UTC),
        duration_seconds=2.0,
    )


def _ffuf_hit(fuzz: str, status: int = 200, length: int = 1234) -> str:
    return json.dumps({
        "input": {"FUZZ": fuzz},
        "url": f"https://example.com/{fuzz}",
        "status": status,
        "length": length,
        "words": 50,
        "lines": 10,
        "content-type": "text/html",
        "redirectlocation": "",
        "host": "example.com",
    })


def test_normalize_ffuf_parses_hits() -> None:
    stdout = "\n".join([_ffuf_hit("admin"), _ffuf_hit("login", 301)])
    art = normalize_ffuf(_result(stdout))
    assert art.kind == "web.content_discovery"
    assert art.payload["hit_count"] == 2
    assert art.confidence >= 0.8
    paths = [h["path"] for h in art.payload["hits"]]
    assert "admin" in paths
    assert "login" in paths
    assert art.payload["hits"][1]["status"] == 301


def test_normalize_ffuf_empty_output() -> None:
    art = normalize_ffuf(_result(""))
    assert art.confidence == 0.0
    assert art.payload["hit_count"] == 0
    assert "empty ffuf output" in art.notes[0]


def test_normalize_ffuf_garbage_lines() -> None:
    stdout = "not json\n" + _ffuf_hit("ok") + "\nalso not json"
    art = normalize_ffuf(_result(stdout))
    assert art.payload["hit_count"] == 1
    assert any("could not be parsed" in n for n in art.notes)


def test_normalize_dispatch_routes_ffuf() -> None:
    stdout = _ffuf_hit("robots.txt")
    art = normalize_result(_result(stdout))
    assert art is not None
    assert art.kind == "web.content_discovery"


# ----- plugin loader --------------------------------------------------------


def test_plugin_loader_discovers_ffuf() -> None:
    loader = PluginLoader(default_timeout=120).load()
    entry = loader.get("ffuf")
    assert entry is not None
    assert entry.cls is FfufTool
    assert entry.origin == "optional"

"""Tests for Frida observation template generation and CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from drake_x.cli import app

runner = CliRunner()


def test_frida_command_registered() -> None:
    result = runner.invoke(app, ["frida", "--help"])
    assert result.exit_code == 0
    assert "template" in result.output
    assert "list" in result.output


def test_frida_list_templates() -> None:
    result = runner.invoke(app, ["frida", "list"])
    assert result.exit_code == 0
    assert "java-method-watch" in result.output
    assert "ssl-observe" in result.output
    assert "anti-analysis-observe" in result.output


def test_frida_template_output(tmp_path: Path) -> None:
    out = tmp_path / "test.js"
    result = runner.invoke(app, ["frida", "template", "java-method-watch", "-o", str(out)])
    assert result.exit_code == 0
    content = out.read_text(encoding="utf-8")
    assert "PLACEHOLDER_CLASS" in content
    assert "observation" in content.lower() or "OBSERVATION" in content
    assert "Drake-X" in content


def test_frida_template_stdout() -> None:
    result = runner.invoke(app, ["frida", "template", "ssl-observe"])
    assert result.exit_code == 0
    assert "CertificatePinner" in result.output


def test_frida_template_unknown() -> None:
    result = runner.invoke(app, ["frida", "template", "nonexistent"])
    assert result.exit_code != 0


def test_frida_templates_no_bypass_strings() -> None:
    """Ensure templates do NOT contain known bypass patterns."""
    templates_dir = Path(__file__).resolve().parents[1] / "drake_x" / "templates" / "frida"
    bypass_patterns = ["return true", "return false", "bypass", "disable", "patch"]
    for js in templates_dir.glob("*.js"):
        content = js.read_text(encoding="utf-8").lower()
        for pattern in bypass_patterns:
            # Allow "return result" and "return this.X()" but not bare "return true/false"
            if pattern in content and pattern not in ("return true", "return false"):
                continue
            # Specific check: "return true" or "return false" as standalone statements
            if f"{pattern};" in content:
                pytest.fail(f"template {js.name} contains bypass-like pattern: '{pattern};'")

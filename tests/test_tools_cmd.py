"""Tests for ``drake tools`` output."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from drake_x.cli import app


runner = CliRunner()


def test_tools_lists_supporting_apk_and_dynamic_toolchains() -> None:
    with (
        patch("drake_x.core.plugin_loader.importlib_metadata.entry_points", return_value=[]),
        patch("drake_x.tools.base.shutil.which", return_value="/usr/bin/fake"),
        patch("drake_x.cli.tools_cmd.shutil.which", return_value="/usr/bin/fake"),
        patch("drake_x.integrations.apk.ghidra.shutil.which", return_value="/opt/ghidra/support/analyzeHeadless"),
        patch("drake_x.integrations.reporting.pandoc.shutil.which", return_value="/usr/bin/pandoc"),
    ):
        result = runner.invoke(app, ["tools"])

    assert result.exit_code == 0
    assert "supported tools" in result.output.lower()
    assert "ghidra" in result.output.lower()
    assert "frida" in result.output.lower()
    assert "apktool" in result.output.lower()
    assert "jadx" in result.output.lower()
    assert "yara" in result.output.lower()
    assert "pandoc" in result.output.lower()

"""Tests for PDF report export via pandoc."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from drake_x.cli import app
from drake_x.integrations.reporting.pandoc import is_available, markdown_to_pdf

runner = CliRunner()


def test_pandoc_availability_check() -> None:
    with patch("drake_x.integrations.reporting.pandoc.shutil.which", return_value=None):
        assert is_available() is False
    with patch("drake_x.integrations.reporting.pandoc.shutil.which", return_value="/usr/bin/pandoc"):
        assert is_available() is True


def test_markdown_to_pdf_missing_pandoc(tmp_path: Path) -> None:
    md = tmp_path / "test.md"
    md.write_text("# Test", encoding="utf-8")
    with patch("drake_x.integrations.reporting.pandoc.is_available", return_value=False):
        ok, err = markdown_to_pdf(md, tmp_path / "test.pdf")
    assert ok is False
    assert "pandoc is not installed" in err


def test_markdown_to_pdf_missing_source(tmp_path: Path) -> None:
    ok, err = markdown_to_pdf(tmp_path / "nope.md", tmp_path / "test.pdf")
    assert ok is False
    assert "not found" in err


def test_report_pdf_format_in_help() -> None:
    result = runner.invoke(app, ["report", "generate", "--help"])
    assert result.exit_code == 0
    assert "pdf" in result.output

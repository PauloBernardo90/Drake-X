"""Tests for IoC VT enrichment: domain/IP lookup, models, CLI."""

from __future__ import annotations

import pytest

from drake_x.integrations.ioc.virustotal import lookup_domain, lookup_ip
from drake_x.models.ioc_enrichment import IocEnrichmentResult, IocVtResult


def test_domain_lookup_no_key() -> None:
    r = lookup_domain("evil.com", api_key="")
    assert r.available is False or r.error == "no API key"


def test_ip_lookup_no_key() -> None:
    r = lookup_ip("8.8.8.8", api_key="")
    assert r.error == "no API key"


def test_ioc_model_defaults() -> None:
    r = IocVtResult()
    assert r.indicator == ""
    assert r.source_label == "virustotal_v3_api"


def test_enrichment_result_empty() -> None:
    r = IocEnrichmentResult()
    assert r.domain_results == []
    assert r.ip_results == []
    assert r.skipped == 0


def test_ioc_cli_registered() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["ioc", "--help"])
    assert result.exit_code == 0
    assert "lookup" in result.output

"""Tests for the v0.3 security headers audit (rule-based finding layer)."""

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
from drake_x.models.artifact import Artifact
from drake_x.models.finding import FindingSeverity, FindingSource
from drake_x.models.scope import ScopeAsset, ScopeFile
from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.normalize.headers import (
    HSTS_WEAK_MAX_AGE_THRESHOLD,
    audit_security_headers,
)
from drake_x.safety.confirm import ConfirmGate, ConfirmMode
from drake_x.scope import parse_target


# ----- helpers --------------------------------------------------------------


def _curl_artifact(headers: dict[str, str], *, scheme: str = "https") -> Artifact:
    return Artifact(
        tool_name="curl",
        kind="web.http_meta",
        payload={
            "final_status": 200,
            "final_headers": dict(headers),
            "hops": [],
            "redirect_chain": [],
        },
        confidence=0.9,
        notes=[],
        raw_command=["curl", "-I", f"{scheme}://example.com/"],
    )


def _httpx_artifact(headers: dict[str, str], *, scheme: str = "https") -> Artifact:
    return Artifact(
        tool_name="httpx",
        kind="web.http_probe",
        payload={
            "url": f"{scheme}://example.com/",
            "host": "example.com",
            "scheme": scheme,
            "status_code": 200,
            "headers": dict(headers),
        },
        confidence=0.9,
        notes=[],
    )


_FULLY_HARDENED = {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "server": "nginx",
}


# ----- positive coverage ----------------------------------------------------


def test_clean_response_produces_no_findings() -> None:
    findings = audit_security_headers([_curl_artifact(_FULLY_HARDENED)])
    assert findings == []


def test_missing_hsts_on_https_is_medium() -> None:
    headers = dict(_FULLY_HARDENED)
    del headers["strict-transport-security"]
    findings = audit_security_headers([_curl_artifact(headers)])
    titles = [f.title for f in findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    hsts = next(f for f in findings if "Strict-Transport-Security" in f.title)
    assert hsts.severity == FindingSeverity.MEDIUM
    assert hsts.source == FindingSource.RULE
    assert hsts.fact_or_inference == "fact"
    assert "CWE-319" in hsts.cwe
    assert "A02:2021" in hsts.owasp
    assert hsts.evidence and hsts.evidence[0].artifact_kind == "web.http_meta"


def test_missing_hsts_on_http_is_silent() -> None:
    """HSTS only applies to HTTPS responses."""
    headers = dict(_FULLY_HARDENED)
    del headers["strict-transport-security"]
    findings = audit_security_headers([_curl_artifact(headers, scheme="http")])
    assert all("Strict-Transport-Security" not in f.title for f in findings)


def test_weak_hsts_max_age_is_low() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["strict-transport-security"] = (
        f"max-age={HSTS_WEAK_MAX_AGE_THRESHOLD - 1}; includeSubDomains"
    )
    findings = audit_security_headers([_curl_artifact(headers)])
    weak = next(f for f in findings if "Weak Strict-Transport-Security" in f.title)
    assert weak.severity == FindingSeverity.LOW
    assert "CWE-319" in weak.cwe


def test_strong_hsts_max_age_is_silent() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["strict-transport-security"] = "max-age=31536000"
    findings = audit_security_headers([_curl_artifact(headers)])
    assert all("Strict-Transport-Security" not in f.title for f in findings)


def test_missing_csp_is_low() -> None:
    headers = dict(_FULLY_HARDENED)
    del headers["content-security-policy"]
    findings = audit_security_headers([_curl_artifact(headers)])
    csp = next(f for f in findings if "Content-Security-Policy" in f.title)
    assert csp.severity == FindingSeverity.LOW
    assert "CWE-693" in csp.cwe
    assert "A05:2021" in csp.owasp


def test_missing_x_content_type_options_is_info() -> None:
    headers = dict(_FULLY_HARDENED)
    del headers["x-content-type-options"]
    findings = audit_security_headers([_curl_artifact(headers)])
    nosniff = next(f for f in findings if "X-Content-Type-Options" in f.title)
    assert nosniff.severity == FindingSeverity.INFO


def test_x_content_type_options_wrong_value_still_flagged() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["x-content-type-options"] = "sniff"
    findings = audit_security_headers([_curl_artifact(headers)])
    assert any("X-Content-Type-Options" in f.title for f in findings)


def test_clickjacking_protected_by_csp_alone() -> None:
    """If CSP has frame-ancestors, X-Frame-Options is no longer required."""
    headers = dict(_FULLY_HARDENED)
    del headers["x-frame-options"]
    headers["content-security-policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    findings = audit_security_headers([_curl_artifact(headers)])
    assert all("clickjacking" not in f.title.lower() for f in findings)


def test_clickjacking_unprotected() -> None:
    headers = dict(_FULLY_HARDENED)
    del headers["x-frame-options"]
    headers["content-security-policy"] = "default-src 'none'"  # no frame-ancestors
    findings = audit_security_headers([_curl_artifact(headers)])
    assert any("clickjacking" in f.title.lower() for f in findings)


def test_missing_referrer_policy_is_info() -> None:
    headers = dict(_FULLY_HARDENED)
    del headers["referrer-policy"]
    findings = audit_security_headers([_curl_artifact(headers)])
    rp = next(f for f in findings if "Referrer-Policy" in f.title)
    assert rp.severity == FindingSeverity.INFO
    assert "CWE-200" in rp.cwe


def test_server_header_version_leak() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["server"] = "nginx/1.18.0 (Ubuntu)"
    findings = audit_security_headers([_curl_artifact(headers)])
    leak = next(f for f in findings if "Server header" in f.title)
    assert leak.severity == FindingSeverity.INFO
    assert "1.18.0" in leak.summary


def test_server_header_no_version_no_finding() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["server"] = "nginx"
    findings = audit_security_headers([_curl_artifact(headers)])
    assert all("Server header" not in f.title for f in findings)


# ----- cookie rules ---------------------------------------------------------


def test_cookie_missing_secure_on_https_is_low() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["set-cookie"] = "sid=abc; Path=/; HttpOnly; SameSite=Lax"
    findings = audit_security_headers([_curl_artifact(headers)])
    secure = next(f for f in findings if "Secure" in f.title and "Set-Cookie" in f.title)
    assert secure.severity == FindingSeverity.LOW
    assert "CWE-1004" in secure.cwe


def test_cookie_missing_httponly() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["set-cookie"] = "sid=abc; Path=/; Secure; SameSite=Lax"
    findings = audit_security_headers([_curl_artifact(headers)])
    assert any("HttpOnly" in f.title for f in findings)


def test_cookie_missing_samesite_is_info() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["set-cookie"] = "sid=abc; Path=/; Secure; HttpOnly"
    findings = audit_security_headers([_curl_artifact(headers)])
    samesite = next(f for f in findings if "SameSite" in f.title)
    assert samesite.severity == FindingSeverity.INFO
    assert "CWE-1275" in samesite.cwe


def test_cookie_secure_not_required_on_http() -> None:
    headers = dict(_FULLY_HARDENED)
    headers["set-cookie"] = "sid=abc; Path=/; HttpOnly; SameSite=Lax"
    findings = audit_security_headers([_curl_artifact(headers, scheme="http")])
    assert all("Secure" not in f.title for f in findings)


def test_audit_handles_both_curl_and_httpx_artifacts() -> None:
    headers = {}  # everything missing — both artifacts should each generate findings
    out = audit_security_headers(
        [_curl_artifact(headers), _httpx_artifact(headers)]
    )
    curl_findings = [f for f in out if f.evidence[0].tool_name == "curl"]
    httpx_findings = [f for f in out if f.evidence[0].tool_name == "httpx"]
    assert curl_findings and httpx_findings


def test_audit_ignores_unrelated_artifacts() -> None:
    other = Artifact(
        tool_name="dig",
        kind="dns.records",
        payload={"records": {"A": ["1.2.3.4"]}},
        confidence=0.9,
        notes=[],
    )
    assert audit_security_headers([other]) == []


# ----- engine integration ---------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    return Workspace.init("test-headers", root=tmp_path)


@pytest.fixture
def in_scope() -> ScopeFile:
    return ScopeFile(
        engagement="t",
        authorization_reference="HEADERS-1",
        in_scope=[ScopeAsset(kind="wildcard_domain", value="example.com")],
        out_of_scope=[],
        allow_active=False,  # passive only
    )


def _ok_curl(stdout: str) -> ToolResult:
    return ToolResult(
        tool_name="curl",
        command=["curl", "-I", "https://example.com/"],
        stdout=stdout,
        stderr="",
        exit_code=0,
        status=ToolResultStatus.OK,
        finished_at=datetime.now(UTC),
        duration_seconds=0.05,
    )


def test_engine_persists_header_audit_findings(workspace, in_scope) -> None:
    """A passive run with a curl artifact must produce + persist header findings."""
    storage = WorkspaceStorage(workspace.db_path)
    loader = PluginLoader(default_timeout=5).load()

    # curl HEAD output for an HTTPS URL with no security headers — every
    # rule should fire.
    curl_stdout = (
        "HTTP/2 200 \r\n"
        "server: nginx/1.18.0\r\n"
        "content-type: text/html\r\n"
        "set-cookie: sid=abc; Path=/\r\n"
        "\r\n"
    )

    async def fake_run(self, target, *, timeout=None):  # noqa: ARG001
        if self.meta.name == "curl":
            return _ok_curl(curl_stdout)
        return ToolResult(
            tool_name=self.meta.name,
            command=[self.meta.binary],
            status=ToolResultStatus.NOT_INSTALLED,
            error_message="not installed (mock)",
            finished_at=datetime.now(UTC),
            duration_seconds=0.0,
        )

    with patch("drake_x.tools.base.shutil.which", return_value="/usr/bin/fake"), \
         patch("drake_x.tools.base.BaseTool.run", new=fake_run):
        engine = Engine(
            workspace=workspace,
            scope=in_scope,
            loader=loader,
            storage=storage,
            confirm=ConfirmGate(mode=ConfirmMode.YES),
        )
        target = parse_target("https://example.com/")
        plan = engine.plan(target=target, profile="passive")
        report = asyncio.run(engine.run(plan))

    # Should have at least HSTS, CSP, X-Content-Type-Options, frame-protection,
    # Referrer-Policy, server-leak, and three cookie findings.
    titles = [f.title for f in report.findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("clickjacking" in t.lower() for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    assert any("Server header" in t for t in titles)
    assert any("Secure" in t and "Set-Cookie" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)

    # All header-audit findings must round-trip via the v2 store.
    persisted = storage.load_findings(report.session.id)
    persisted_titles = [f.title for f in persisted]
    assert any("Strict-Transport-Security" in t for t in persisted_titles)
    # And they must be tagged as security-header rule findings.
    rule_findings = [f for f in persisted if f.source == FindingSource.RULE]
    assert all("security-header" in f.tags for f in rule_findings)

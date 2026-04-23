"""Tests for drake_x.sandbox.report — execution report model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.sandbox.report import SandboxReport, now_utc_iso


class TestSandboxReport:
    def test_default_run_id(self) -> None:
        r = SandboxReport()
        assert r.run_id.startswith("sbx-")
        assert len(r.run_id) > 4

    def test_to_dict(self) -> None:
        r = SandboxReport(
            sample_path="/test.apk",
            sample_sha256="abc123",
            backend="firejail",
            status="success",
            exit_code=0,
            stdout="hello",
            stderr="",
            isolation_verified=True,
        )
        d = r.to_dict()
        assert d["sample"]["path"] == "/test.apk"
        assert d["sample"]["sha256"] == "abc123"
        assert d["execution"]["backend"] == "firejail"
        assert d["outcome"]["status"] == "success"
        assert d["outcome"]["exit_code"] == 0
        assert d["output"]["stdout"] == "hello"
        assert d["isolation"]["verified"] is True

    def test_to_json(self) -> None:
        r = SandboxReport(status="success")
        j = r.to_json()
        data = json.loads(j)
        assert data["outcome"]["status"] == "success"

    def test_write_json(self, tmp_path: Path) -> None:
        r = SandboxReport(status="error", error="test failure")
        out = tmp_path / "report.json"
        r.write_json(out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["outcome"]["error"] == "test failure"

    def test_audit_observations(self) -> None:
        r = SandboxReport()
        r.audit_observations.append("Test observation 1")
        r.audit_observations.append("Test observation 2")
        d = r.to_dict()
        assert len(d["audit"]["observations"]) == 2

    def test_isolation_notes(self) -> None:
        r = SandboxReport()
        r.isolation_notes.append("Firejail verified")
        d = r.to_dict()
        assert "Firejail verified" in d["isolation"]["notes"]


class TestNowUtcIso:
    def test_returns_string(self) -> None:
        ts = now_utc_iso()
        assert isinstance(ts, str)
        assert "T" in ts
        assert "+" in ts or "Z" in ts

"""Tests for drake_x.cli.integrity_cmd — integrity CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from drake_x.cli.integrity_cmd import app as integrity_app
from drake_x.integrity.ledger import IntegrityLedger
from drake_x.integrity.models import (
    ArtifactRecord,
    CustodyAction,
    CustodyEvent,
    CustodyStatus,
    IntegrityReport,
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def sample_report() -> IntegrityReport:
    sha = "a" * 64
    return IntegrityReport(
        run_id="run-cli-test",
        sample_sha256=sha,
        sample_identity={
            "file_name": "sample.apk",
            "file_size": 1000,
            "md5": "m" * 32,
            "sha1": "s" * 40,
            "sha256": sha,
        },
        artifacts=[
            ArtifactRecord(
                artifact_type="apk",
                file_name="sample.apk",
                sha256=sha,
                parent_sha256=sha,
                run_id="run-cli-test",
            ),
        ],
        custody_events=[
            CustodyEvent(
                run_id="run-cli-test",
                action=CustodyAction.INGEST,
                artifact_sha256=sha,
                status=CustodyStatus.OK,
            ),
        ],
        verified=True,
        report_sha256="b" * 64,
    )


@pytest.fixture
def populated_ledger(tmp_path: Path, sample_report: IntegrityReport) -> Path:
    """Create a ledger with one run recorded."""
    db_path = tmp_path / "ledger.db"
    ledger = IntegrityLedger(db_path)
    for event in sample_report.custody_events:
        ledger.append_custody_event(event)
    ledger.append_integrity_report(sample_report)
    ledger.append_verification(
        run_id=sample_report.run_id,
        verified=True,
        timestamp="2025-01-15T10:00:00+00:00",
    )
    return db_path


@pytest.fixture
def report_file(tmp_path: Path, sample_report: IntegrityReport) -> Path:
    path = tmp_path / "integrity_report.json"
    path.write_text(
        json.dumps(sample_report.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )
    return path


class TestVerifyLedger:
    def test_valid_ledger_passes(self, runner: CliRunner, populated_ledger: Path) -> None:
        result = runner.invoke(integrity_app, ["verify-ledger", "--ledger", str(populated_ledger)])
        assert result.exit_code == 0
        assert "VERIFIED" in result.stdout

    def test_missing_ledger_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            integrity_app,
            ["verify-ledger", "--ledger", str(tmp_path / "nonexistent.db")],
        )
        assert result.exit_code == 2

    def test_verify_specific_run(self, runner: CliRunner, populated_ledger: Path) -> None:
        result = runner.invoke(
            integrity_app,
            ["verify-ledger", "--ledger", str(populated_ledger), "--run-id", "run-cli-test"],
        )
        assert result.exit_code == 0
        assert "VERIFIED" in result.stdout

    def test_detects_tampering(
        self, runner: CliRunner, populated_ledger: Path
    ) -> None:
        # Tamper with the ledger
        import sqlite3
        conn = sqlite3.connect(str(populated_ledger))
        conn.execute(
            "UPDATE ledger_entries SET payload = ? WHERE seq = 1",
            ('{"tampered": true}',),
        )
        conn.commit()
        conn.close()

        result = runner.invoke(
            integrity_app, ["verify-ledger", "--ledger", str(populated_ledger)]
        )
        assert result.exit_code == 1
        assert "FAILED" in result.stdout


class TestVerifyReport:
    def test_valid_report_passes(self, runner: CliRunner, report_file: Path) -> None:
        result = runner.invoke(integrity_app, ["verify-report", str(report_file)])
        assert result.exit_code == 0
        assert "VERIFIED" in result.stdout

    def test_missing_file_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            integrity_app, ["verify-report", str(tmp_path / "missing.json")]
        )
        assert result.exit_code == 2

    def test_invalid_json_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all")
        result = runner.invoke(integrity_app, ["verify-report", str(bad)])
        assert result.exit_code == 2

    def test_corrupt_report_fails(
        self, runner: CliRunner, tmp_path: Path, sample_report: IntegrityReport
    ) -> None:
        # Create a report with mismatched sha256
        data = sample_report.model_dump(mode="json")
        data["sample_identity"]["sha256"] = "different" * 8
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(data, default=str))

        result = runner.invoke(integrity_app, ["verify-report", str(bad)])
        assert result.exit_code == 1
        assert "FAILED" in result.stdout


class TestExportBundle:
    def test_from_file(
        self, runner: CliRunner, report_file: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "bundle.stix.json"
        result = runner.invoke(
            integrity_app,
            ["export-bundle", str(report_file), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        bundle = json.loads(out.read_text())
        assert bundle["type"] == "bundle"

    def test_from_ledger_by_run_id(
        self, runner: CliRunner, populated_ledger: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "bundle.stix.json"
        result = runner.invoke(
            integrity_app,
            [
                "export-bundle",
                "--run-id", "run-cli-test",
                "--ledger", str(populated_ledger),
                "--output", str(out),
            ],
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_unknown_run_id_fails(
        self, runner: CliRunner, populated_ledger: Path
    ) -> None:
        result = runner.invoke(
            integrity_app,
            [
                "export-bundle",
                "--run-id", "run-nonexistent",
                "--ledger", str(populated_ledger),
            ],
        )
        assert result.exit_code == 1

    def test_no_input_fails(self, runner: CliRunner) -> None:
        result = runner.invoke(integrity_app, ["export-bundle"])
        assert result.exit_code == 2


class TestListRuns:
    def test_lists_runs(self, runner: CliRunner, populated_ledger: Path) -> None:
        result = runner.invoke(
            integrity_app, ["list-runs", "--ledger", str(populated_ledger)]
        )
        assert result.exit_code == 0
        assert "run-cli-test" in result.stdout

    def test_empty_ledger(self, runner: CliRunner, tmp_path: Path) -> None:
        empty = tmp_path / "empty.db"
        IntegrityLedger(empty)  # creates empty db
        result = runner.invoke(integrity_app, ["list-runs", "--ledger", str(empty)])
        assert result.exit_code == 0
        assert "No runs found" in result.stdout


class TestShowRun:
    def test_shows_run(self, runner: CliRunner, populated_ledger: Path) -> None:
        result = runner.invoke(
            integrity_app,
            ["show-run", "run-cli-test", "--ledger", str(populated_ledger)],
        )
        assert result.exit_code == 0
        assert "run-cli-test" in result.stdout
        assert "custody_event" in result.stdout

    def test_unknown_run_fails(
        self, runner: CliRunner, populated_ledger: Path
    ) -> None:
        result = runner.invoke(
            integrity_app,
            ["show-run", "run-nonexistent", "--ledger", str(populated_ledger)],
        )
        assert result.exit_code == 1

    def test_detailed_shows_payload(
        self, runner: CliRunner, populated_ledger: Path
    ) -> None:
        result = runner.invoke(
            integrity_app,
            [
                "show-run", "run-cli-test",
                "--ledger", str(populated_ledger),
                "--detailed",
            ],
        )
        assert result.exit_code == 0
        # Detailed output should contain JSON payload fields
        assert "sha256" in result.stdout or "action" in result.stdout


class TestLedgerWorkspaceIntegration:
    def test_get_integrity_report(
        self, populated_ledger: Path, sample_report: IntegrityReport
    ) -> None:
        ledger = IntegrityLedger(populated_ledger)
        retrieved = ledger.get_integrity_report("run-cli-test")
        assert retrieved is not None
        assert retrieved.run_id == sample_report.run_id
        assert retrieved.sample_sha256 == sample_report.sample_sha256

    def test_get_nonexistent_returns_none(self, populated_ledger: Path) -> None:
        ledger = IntegrityLedger(populated_ledger)
        assert ledger.get_integrity_report("run-nonexistent") is None

    def test_run_summary_found(self, populated_ledger: Path) -> None:
        ledger = IntegrityLedger(populated_ledger)
        summary = ledger.run_summary("run-cli-test")
        assert summary["found"] is True
        assert summary["entry_count"] == 3  # event + report + verification
        assert summary["verified"] is True

    def test_run_summary_not_found(self, populated_ledger: Path) -> None:
        ledger = IntegrityLedger(populated_ledger)
        summary = ledger.run_summary("run-missing")
        assert summary["found"] is False


class TestSharedDbMode:
    def test_ledger_coexists_with_other_schemas(self, tmp_path: Path) -> None:
        """Verify ledger tables don't conflict with a pre-existing DB schema."""
        import sqlite3

        db_path = tmp_path / "shared.db"
        # Create a DB with a non-ledger table first
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE other_stuff (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO other_stuff VALUES (1, 'existing')")
        conn.commit()
        conn.close()

        # Now create a ledger on the same DB
        ledger = IntegrityLedger(db_path)
        ledger.append_custody_event(CustodyEvent(
            run_id="run-shared",
            action=CustodyAction.INGEST,
            status=CustodyStatus.OK,
        ))

        # Verify both tables exist and are queryable
        conn = sqlite3.connect(str(db_path))
        ls_count = conn.execute(
            "SELECT COUNT(*) FROM ledger_entries"
        ).fetchone()[0]
        other_count = conn.execute(
            "SELECT COUNT(*) FROM other_stuff"
        ).fetchone()[0]
        conn.close()

        assert ls_count == 1
        assert other_count == 1

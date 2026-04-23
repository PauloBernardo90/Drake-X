"""Tests for finalize_integrity_outputs — end-to-end integrity pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drake_x.integrity.models import (
    ArtifactRecord,
    CustodyAction,
    CustodyEvent,
    CustodyStatus,
    IntegrityReport,
)
from drake_x.integrity.reporting import finalize_integrity_outputs


@pytest.fixture
def sample_report() -> IntegrityReport:
    sha = "a" * 64
    return IntegrityReport(
        run_id="run-test",
        sample_sha256=sha,
        sample_identity={"sha256": sha, "file_name": "t.apk"},
        artifacts=[
            ArtifactRecord(
                artifact_type="apk",
                file_name="t.apk",
                sha256=sha,
                parent_sha256=sha,
                run_id="run-test",
            ),
        ],
        custody_events=[
            CustodyEvent(
                run_id="run-test",
                action=CustodyAction.INGEST,
                status=CustodyStatus.OK,
            ),
        ],
        verified=True,
        report_sha256="b" * 64,
    )


class TestFinalizeIntegrityOutputs:
    def test_writes_integrity_report_only(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        outputs = finalize_integrity_outputs(sample_report, tmp_path)
        assert "integrity_report" in outputs
        assert Path(outputs["integrity_report"]).exists()

    def test_no_signature_by_default(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        outputs = finalize_integrity_outputs(sample_report, tmp_path)
        assert "signature" not in outputs

    def test_no_stix_by_default(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        outputs = finalize_integrity_outputs(sample_report, tmp_path)
        assert "stix_provenance" not in outputs

    def test_no_ledger_by_default(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        outputs = finalize_integrity_outputs(sample_report, tmp_path)
        assert "ledger" not in outputs

    def test_stix_generation(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        outputs = finalize_integrity_outputs(
            sample_report, tmp_path, write_stix=True
        )
        assert "stix_provenance" in outputs
        assert Path(outputs["stix_provenance"]).exists()
        # Verify it's valid JSON
        data = json.loads(Path(outputs["stix_provenance"]).read_text())
        assert data["type"] == "bundle"

    def test_ledger_append(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        ledger_path = tmp_path / "ledger.db"
        outputs = finalize_integrity_outputs(
            sample_report, tmp_path, ledger_path=ledger_path
        )
        assert "ledger" in outputs
        assert ledger_path.exists()

        # Verify ledger contains entries
        from drake_x.integrity.ledger import IntegrityLedger
        ledger = IntegrityLedger(ledger_path)
        entries = ledger.read_run("run-test")
        assert len(entries) >= 2  # custody event + report + verification

    def test_signing_graceful_without_gpg(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value=None):
            outputs = finalize_integrity_outputs(
                sample_report, tmp_path, sign=True
            )
            assert "signature_error" in outputs
            assert "not installed" in outputs["signature_error"]

    def test_successful_signing(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            with patch("drake_x.integrity.signing.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr=b"")
                outputs = finalize_integrity_outputs(
                    sample_report, tmp_path, sign=True
                )
                assert "signature" in outputs

    def test_all_outputs_together(
        self, sample_report: IntegrityReport, tmp_path: Path
    ) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            with patch("drake_x.integrity.signing.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr=b"")
                outputs = finalize_integrity_outputs(
                    sample_report,
                    tmp_path,
                    sign=True,
                    write_stix=True,
                    ledger_path=tmp_path / "ledger.db",
                )
                assert "integrity_report" in outputs
                assert "signature" in outputs
                assert "stix_provenance" in outputs
                assert "ledger" in outputs

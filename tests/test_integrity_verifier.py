"""Tests for drake_x.integrity.verifier — fail-closed integrity checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.integrity.exceptions import IntegrityVerificationError
from drake_x.integrity.hashing import compute_file_hashes
from drake_x.integrity.models import (
    ArtifactRecord,
    CustodyAction,
    CustodyEvent,
    CustodyStatus,
    IntegrityReport,
)
from drake_x.integrity.verifier import IntegrityVerifier, verify_file_integrity


@pytest.fixture
def valid_report() -> IntegrityReport:
    sha = "abcdef1234567890" * 4
    return IntegrityReport(
        run_id="run-test123",
        sample_sha256=sha,
        sample_identity={"sha256": sha, "md5": "m" * 32, "sha1": "s" * 40},
        artifacts=[
            ArtifactRecord(
                artifact_type="apk",
                file_name="test.apk",
                sha256=sha,
                parent_sha256=sha,
                run_id="run-test123",
            ),
        ],
        custody_events=[
            CustodyEvent(
                run_id="run-test123",
                action=CustodyAction.INGEST,
                artifact_sha256=sha,
                status=CustodyStatus.OK,
            ),
        ],
        report_sha256="a" * 64,
    )


class TestIntegrityVerifier:
    def test_valid_report_passes(self, valid_report: IntegrityReport) -> None:
        verifier = IntegrityVerifier()
        assert verifier.verify(valid_report) is True

    def test_missing_run_id_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.run_id = ""
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError):
            verifier.verify(valid_report)

    def test_missing_sample_sha256_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.sample_sha256 = ""
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError):
            verifier.verify(valid_report)

    def test_identity_sha256_mismatch_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.sample_identity["sha256"] = "different" * 8
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError, match="does not match"):
            verifier.verify(valid_report)

    def test_missing_identity_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.sample_identity = {}
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError):
            verifier.verify(valid_report)

    def test_artifact_run_id_mismatch_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.artifacts[0] = ArtifactRecord(
            artifact_type="apk",
            file_name="test.apk",
            sha256="a" * 64,
            run_id="run-WRONG",
            parent_sha256=valid_report.sample_sha256,
        )
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError, match="run_id"):
            verifier.verify(valid_report)

    def test_artifact_missing_sha256_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.artifacts[0] = ArtifactRecord(
            artifact_type="apk",
            file_name="test.apk",
            sha256="",
            run_id="run-test123",
        )
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError, match="missing SHA-256"):
            verifier.verify(valid_report)

    def test_custody_run_id_mismatch_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.custody_events = [
            CustodyEvent(
                run_id="run-WRONG",
                action=CustodyAction.INGEST,
                status=CustodyStatus.OK,
            ),
        ]
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError, match="run_id"):
            verifier.verify(valid_report)

    def test_missing_ingest_event_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.custody_events = [
            CustodyEvent(
                run_id="run-test123",
                action=CustodyAction.ANALYZE,
                status=CustodyStatus.OK,
            ),
        ]
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError, match="ingest"):
            verifier.verify(valid_report)

    def test_no_custody_events_fails(self, valid_report: IntegrityReport) -> None:
        valid_report.custody_events = []
        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError):
            verifier.verify(valid_report)

    def test_artifact_file_hash_verified(self, tmp_path: Path) -> None:
        """If artifact file exists, verify its hash matches."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"test content")
        identity = compute_file_hashes(f)

        report = IntegrityReport(
            run_id="run-test",
            sample_sha256=identity.sha256,
            sample_identity=identity.to_dict(),
            artifacts=[
                ArtifactRecord(
                    artifact_type="test",
                    file_name="test.bin",
                    file_path=str(f),
                    sha256=identity.sha256,
                    parent_sha256=identity.sha256,
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
        )
        verifier = IntegrityVerifier()
        assert verifier.verify(report) is True

    def test_artifact_file_tampered_fails(self, tmp_path: Path) -> None:
        """If artifact file has been modified, verification must fail."""
        f = tmp_path / "test.bin"
        f.write_bytes(b"original content")
        identity = compute_file_hashes(f)

        report = IntegrityReport(
            run_id="run-test",
            sample_sha256=identity.sha256,
            sample_identity=identity.to_dict(),
            artifacts=[
                ArtifactRecord(
                    artifact_type="test",
                    file_name="test.bin",
                    file_path=str(f),
                    sha256=identity.sha256,
                    parent_sha256=identity.sha256,
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
        )

        # Tamper with the file
        f.write_bytes(b"tampered content!!!")

        verifier = IntegrityVerifier()
        with pytest.raises(IntegrityVerificationError, match="hash mismatch"):
            verifier.verify(report)


class TestVerifyFileIntegrity:
    def test_matching_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"test content")
        identity = compute_file_hashes(f)
        assert verify_file_integrity(f, identity.sha256) is True

    def test_mismatching_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"test content")
        with pytest.raises(IntegrityVerificationError):
            verify_file_integrity(f, "wrong_hash" * 8)

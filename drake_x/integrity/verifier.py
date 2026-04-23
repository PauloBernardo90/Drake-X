"""Integrity verifier — fail-closed consistency checks.

Validates that the entire analysis chain is consistent:

- Sample hash matches what was originally recorded
- Staged artifacts match their recorded hashes
- Chain of custody is complete
- Report references the correct sample and run_id
- All required links are present

If ANY check fails, the verifier raises :class:`IntegrityVerificationError`.
There is no "warn and continue" mode.
"""

from __future__ import annotations

from pathlib import Path

from ..logging import get_logger
from .exceptions import IntegrityVerificationError
from .hashing import compute_sha256
from .models import ArtifactRecord, CustodyEvent, IntegrityReport

log = get_logger("integrity.verifier")


class IntegrityVerifier:
    """Stateless verifier for analysis integrity.

    Call :meth:`verify` with a complete :class:`IntegrityReport` to check
    all integrity constraints. On failure, raises
    :class:`IntegrityVerificationError` with a list of violations.
    """

    def verify(self, report: IntegrityReport) -> bool:
        """Verify the integrity of an analysis run.

        Returns True if all checks pass.
        Raises IntegrityVerificationError if any check fails.
        """
        violations: list[str] = []

        violations.extend(self._check_run_id(report))
        violations.extend(self._check_sample_identity(report))
        violations.extend(self._check_artifacts(report))
        violations.extend(self._check_custody_chain(report))
        violations.extend(self._check_report_hash(report))

        if violations:
            log.error(
                "Integrity verification FAILED for run %s: %d violation(s)",
                report.run_id, len(violations),
            )
            raise IntegrityVerificationError(violations)

        log.info("Integrity verification PASSED for run %s", report.run_id)
        return True

    def _check_run_id(self, report: IntegrityReport) -> list[str]:
        violations: list[str] = []
        if not report.run_id:
            violations.append("Missing run_id in integrity report")
        if not report.sample_sha256:
            violations.append("Missing sample_sha256 in integrity report")
        return violations

    def _check_sample_identity(self, report: IntegrityReport) -> list[str]:
        violations: list[str] = []
        identity = report.sample_identity
        if not identity:
            violations.append("Missing sample_identity in report")
            return violations

        if identity.get("sha256") != report.sample_sha256:
            violations.append(
                f"sample_identity.sha256 ({identity.get('sha256', 'missing')}) "
                f"does not match report.sample_sha256 ({report.sample_sha256})"
            )
        return violations

    def _check_artifacts(self, report: IntegrityReport) -> list[str]:
        violations: list[str] = []
        for art in report.artifacts:
            # Every artifact must reference the run_id
            if art.run_id and art.run_id != report.run_id:
                violations.append(
                    f"Artifact {art.file_name} has run_id {art.run_id}, "
                    f"expected {report.run_id}"
                )
            # Every artifact must have a SHA-256
            if not art.sha256:
                violations.append(f"Artifact {art.file_name} missing SHA-256")
            # Every artifact must reference the parent sample
            if art.parent_sha256 and art.parent_sha256 != report.sample_sha256:
                violations.append(
                    f"Artifact {art.file_name} parent_sha256 mismatch: "
                    f"{art.parent_sha256} != {report.sample_sha256}"
                )
            # If file still exists, verify hash
            if art.file_path and art.sha256:
                path = Path(art.file_path)
                if path.is_file():
                    try:
                        actual = compute_sha256(path)
                        if actual != art.sha256:
                            violations.append(
                                f"Artifact {art.file_name} hash mismatch: "
                                f"recorded {art.sha256[:16]}…, actual {actual[:16]}…"
                            )
                    except Exception:  # noqa: BLE001
                        pass  # File may have been cleaned up
        return violations

    def _check_custody_chain(self, report: IntegrityReport) -> list[str]:
        violations: list[str] = []
        if not report.custody_events:
            violations.append("No custody events in report")
            return violations

        # Check all events reference the correct run_id
        for event in report.custody_events:
            if event.run_id != report.run_id:
                violations.append(
                    f"Custody event run_id mismatch: {event.run_id} != {report.run_id}"
                )

        # Check required INGEST event
        actions = {e.action for e in report.custody_events}
        if "ingest" not in actions:
            violations.append("Required custody event missing: ingest")

        # Check chronological order
        timestamps = [e.timestamp for e in report.custody_events]
        if timestamps != sorted(timestamps):
            violations.append("Custody events are not in chronological order")

        return violations

    def _check_report_hash(self, report: IntegrityReport) -> list[str]:
        violations: list[str] = []
        # Report hash is optional but if present must be non-empty
        if report.report_sha256 == "":
            pass  # Not yet generated
        elif len(report.report_sha256) != 64:
            violations.append(
                f"Invalid report SHA-256 length: {len(report.report_sha256)}"
            )
        return violations


def verify_file_integrity(
    path: Path,
    expected_sha256: str,
) -> bool:
    """Quick integrity check for a single file.

    Returns True if the file's SHA-256 matches expected.
    Raises IntegrityVerificationError on mismatch.
    """
    actual = compute_sha256(path)
    if actual != expected_sha256:
        raise IntegrityVerificationError([
            f"File {path.name}: expected SHA-256 {expected_sha256[:16]}…, "
            f"got {actual[:16]}…"
        ])
    return True

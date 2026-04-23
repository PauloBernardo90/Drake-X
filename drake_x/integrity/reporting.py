"""Integrity report generation — tie everything together.

Produces a complete :class:`IntegrityReport` from the custody chain,
version info, and verification results. The report itself is hashed
for tamper evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..logging import get_logger
from .chain import CustodyChain
from .hashing import SampleIdentity, hash_bytes
from .models import (
    AnalysisVersionInfo,
    ExecutionContext,
    IntegrityReport,
)
from .verifier import IntegrityVerifier

log = get_logger("integrity.reporting")


def build_integrity_report(
    *,
    sample_identity: SampleIdentity,
    chain: CustodyChain,
    execution_context: ExecutionContext,
    version_info: AnalysisVersionInfo,
    verify: bool = True,
) -> IntegrityReport:
    """Build a complete integrity report from the analysis chain.

    Parameters
    ----------
    sample_identity:
        Hashes and metadata of the original sample.
    chain:
        The chain of custody with all events and artifacts.
    execution_context:
        Execution configuration snapshot.
    version_info:
        Pipeline and tool version snapshot.
    verify:
        If True, run integrity verification and include results.
    """
    report = IntegrityReport(
        run_id=chain.run_id,
        sample_sha256=sample_identity.sha256,
        sample_identity=sample_identity.to_dict(),
        execution_context=execution_context,
        version_info=version_info,
        artifacts=chain.artifacts,
        custody_events=chain.events,
    )

    # Self-hash: compute SHA-256 of the report content (before this field)
    report_json = json.dumps(
        report.model_dump(mode="json", exclude={"report_sha256", "verified", "verification_errors"}),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    report.report_sha256 = hash_bytes(report_json)

    # Verify if requested
    if verify:
        verifier = IntegrityVerifier()
        try:
            verifier.verify(report)
            report.verified = True
            report.verification_errors = []
        except Exception as exc:
            report.verified = False
            if hasattr(exc, "violations"):
                report.verification_errors = exc.violations
            else:
                report.verification_errors = [str(exc)]

    return report


def write_integrity_report(
    report: IntegrityReport,
    output_path: Path,
) -> Path:
    """Write the integrity report as JSON."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(report.model_dump(mode="json"), indent=2, default=str)
    output_path.write_text(content, encoding="utf-8")
    log.info("Integrity report written to %s", output_path)
    return output_path

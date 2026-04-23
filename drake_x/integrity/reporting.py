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


def finalize_integrity_outputs(
    report: IntegrityReport,
    output_dir: Path,
    *,
    sign: bool = False,
    signing_key: str = "",
    write_stix: bool = False,
    ledger_path: Path | None = None,
) -> dict[str, str]:
    """Write all integrity-related outputs: JSON report, signature, STIX, ledger.

    Returns a dict mapping output kind → path (or status message).
    """
    output_dir = Path(output_dir)
    outputs: dict[str, str] = {}

    # 1. Write the integrity report JSON
    report_path = output_dir / "integrity_report.json"
    write_integrity_report(report, report_path)
    outputs["integrity_report"] = str(report_path)

    # 2. Optional GPG signing
    if sign:
        from .signing import sign_file
        sig_result = sign_file(report_path, key_id=signing_key)
        if sig_result.signed:
            outputs["signature"] = sig_result.signature_path
            outputs["signing_key"] = sig_result.key_fingerprint or "default"
        else:
            outputs["signature_error"] = sig_result.error

    # 3. Optional STIX provenance bundle
    if write_stix:
        from .stix_bundle import render_provenance_stix
        stix_text = render_provenance_stix(report)
        if stix_text:
            stix_path = output_dir / "integrity_provenance.stix.json"
            stix_path.write_text(stix_text, encoding="utf-8")
            outputs["stix_provenance"] = str(stix_path)

    # 4. Optional ledger append
    if ledger_path is not None:
        from .ledger import IntegrityLedger
        try:
            ledger = IntegrityLedger(ledger_path)
            for event in report.custody_events:
                ledger.append_custody_event(event)
            ledger.append_integrity_report(report)
            ledger.append_verification(
                run_id=report.run_id,
                verified=report.verified,
                timestamp=report.generated_at,
                details={"errors": report.verification_errors},
            )
            outputs["ledger"] = str(ledger_path)
        except Exception as exc:  # noqa: BLE001
            outputs["ledger_error"] = str(exc)
            log.warning("Ledger append failed: %s", exc)

    return outputs

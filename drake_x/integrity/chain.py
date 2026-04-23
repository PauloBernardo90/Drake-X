"""Chain of custody tracker — chronological evidence provenance log.

The custody chain records every significant action performed on or with
a sample during analysis. Events are append-only and ordered by timestamp.

Usage::

    chain = CustodyChain(run_id="run-abc123", sample_sha256="deadbeef...")
    chain.record(CustodyAction.INGEST, artifact_sha256="deadbeef...",
                 actor="apk_analyze", details="Original APK ingested")
    chain.record(CustodyAction.STAGE, ...)
    chain.verify_completeness()  # raises if required events missing
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging import get_logger
from .exceptions import CustodyChainError, MissingRunIdError
from .hashing import SampleIdentity, compute_sha256
from .models import (
    ArtifactRecord,
    CustodyAction,
    CustodyEvent,
    CustodyStatus,
)

log = get_logger("integrity.chain")

# Events that must be present for a complete analysis
_REQUIRED_EVENTS = {CustodyAction.INGEST}


class CustodyChain:
    """Append-only chain of custody for one analysis run.

    Every event references the ``run_id`` and optionally the
    ``artifact_sha256`` of the artifact involved.
    """

    def __init__(self, *, run_id: str, sample_sha256: str) -> None:
        if not run_id:
            raise MissingRunIdError("Cannot create custody chain without run_id")
        if not sample_sha256:
            raise CustodyChainError("Cannot create custody chain without sample SHA-256")

        self._run_id = run_id
        self._sample_sha256 = sample_sha256
        self._events: list[CustodyEvent] = []
        self._artifacts: list[ArtifactRecord] = []

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def sample_sha256(self) -> str:
        return self._sample_sha256

    @property
    def events(self) -> list[CustodyEvent]:
        return list(self._events)

    @property
    def artifacts(self) -> list[ArtifactRecord]:
        return list(self._artifacts)

    def record(
        self,
        action: CustodyAction,
        *,
        artifact_sha256: str = "",
        actor: str = "",
        details: str = "",
        status: CustodyStatus = CustodyStatus.OK,
    ) -> CustodyEvent:
        """Record a custody event."""
        event = CustodyEvent(
            run_id=self._run_id,
            action=action,
            artifact_sha256=artifact_sha256 or self._sample_sha256,
            actor=actor,
            details=details,
            status=status,
        )
        self._events.append(event)

        log.info(
            "[%s] %s: %s (actor=%s, status=%s)",
            self._run_id, action.value, details[:80], actor, status.value,
        )
        return event

    def register_artifact(
        self,
        *,
        artifact_type: str,
        file_path: Path,
        sha256: str = "",
        notes: str = "",
    ) -> ArtifactRecord:
        """Register an artifact with integrity metadata.

        If ``sha256`` is not provided, it is computed from the file.
        """
        path = Path(file_path)
        if not sha256 and path.is_file():
            sha256 = compute_sha256(path)

        try:
            file_size = path.stat().st_size if path.is_file() else 0
        except OSError:
            file_size = 0

        record = ArtifactRecord(
            artifact_id=f"art-{len(self._artifacts):04d}",
            artifact_type=artifact_type,
            file_name=path.name,
            file_path=str(path),
            sha256=sha256,
            file_size=file_size,
            parent_sha256=self._sample_sha256,
            run_id=self._run_id,
            notes=notes,
        )
        self._artifacts.append(record)

        # Also record custody event
        self.record(
            CustodyAction.ARTIFACT_REGISTER,
            artifact_sha256=sha256,
            actor="integrity",
            details=f"Registered {artifact_type}: {path.name}",
        )

        return record

    def record_failure(self, *, actor: str, details: str) -> CustodyEvent:
        """Record a failure event."""
        return self.record(
            CustodyAction.FAIL,
            actor=actor,
            details=details,
            status=CustodyStatus.FAILED,
        )

    def verify_completeness(self) -> list[str]:
        """Verify the custody chain has all required events.

        Returns a list of violation descriptions. Empty list = valid.
        """
        violations: list[str] = []

        # Check run_id consistency
        for event in self._events:
            if event.run_id != self._run_id:
                violations.append(
                    f"Event run_id mismatch: expected {self._run_id}, "
                    f"got {event.run_id}"
                )

        # Check required events
        actions_seen = {e.action for e in self._events}
        for required in _REQUIRED_EVENTS:
            if required not in actions_seen:
                violations.append(f"Required event missing: {required.value}")

        # Check chronological order
        for i in range(1, len(self._events)):
            if self._events[i].timestamp < self._events[i - 1].timestamp:
                violations.append(
                    f"Events out of chronological order at index {i}"
                )

        return violations

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full custody chain."""
        return {
            "run_id": self._run_id,
            "sample_sha256": self._sample_sha256,
            "event_count": len(self._events),
            "artifact_count": len(self._artifacts),
            "events": [e.model_dump(mode="json") for e in self._events],
            "artifacts": [a.model_dump(mode="json") for a in self._artifacts],
        }

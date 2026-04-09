"""Session data model.

A session represents one invocation of ``drake-x scan``: target, profile,
the tools that ran (or were skipped), and overall status. The persistence
layer (:mod:`drake_x.session_store`) is responsible for serializing this.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from .target import Target


class SessionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"   # ran, but some tools failed/were missing
    FAILED = "failed"


def _new_session_id() -> str:
    return uuid4().hex[:12]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Session(BaseModel):
    """A single recon session."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=_new_session_id)
    target: Target
    profile: str
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    status: SessionStatus = SessionStatus.PENDING

    tools_planned: list[str] = Field(default_factory=list)
    tools_ran: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    ai_enabled: bool = False
    ai_model: str | None = None
    ai_summary: str | None = None

    report_path: str | None = None

    def mark_running(self) -> None:
        self.status = SessionStatus.RUNNING

    def mark_finished(self, *, partial: bool = False, failed: bool = False) -> None:
        self.finished_at = _utcnow()
        if failed:
            self.status = SessionStatus.FAILED
        elif partial:
            self.status = SessionStatus.PARTIAL
        else:
            self.status = SessionStatus.COMPLETED

    @property
    def duration_seconds(self) -> float | None:
        if not self.finished_at:
            return None
        return (self.finished_at - self.started_at).total_seconds()

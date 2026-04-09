"""Result of a single tool invocation."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ToolResultStatus(StrEnum):
    OK = "ok"
    NONZERO = "nonzero"      # ran, exited non-zero, but no exception
    TIMEOUT = "timeout"
    NOT_INSTALLED = "not_installed"
    ERROR = "error"          # internal/wrapper failure


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ToolResult(BaseModel):
    """Captured result of running an individual tool."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool_name: str
    command: list[str]
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    status: ToolResultStatus = ToolResultStatus.OK
    error_message: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == ToolResultStatus.OK

    @property
    def ran(self) -> bool:
        return self.status in {ToolResultStatus.OK, ToolResultStatus.NONZERO}

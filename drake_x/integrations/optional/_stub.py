"""Shared scaffolding for optional integration stubs.

A stub is a real :class:`BaseTool` subclass with concrete metadata and a
concrete ``build_command``, but its ``run`` refuses to execute unless an
operator explicitly opts in. This lets the rest of the framework reason
about the integration (display it in `tools list`, include it in plans)
without actually launching anything we have not validated yet.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ...models.target import Target
from ...models.tool_result import ToolResult, ToolResultStatus
from ...tools.base import BaseTool


class StubTool(BaseTool):
    """Base class for unimplemented integrations.

    Subclasses MUST set :attr:`meta` and override :meth:`build_command` so
    we can show the planned argv during dry-runs. They inherit a
    :meth:`run` that always returns a NOT_INSTALLED-style result with a
    clear ``stub`` marker.
    """

    stub_status: str = "not yet implemented"

    async def run(self, target: Target, *, timeout: int | None = None) -> ToolResult:  # noqa: ARG002
        cmd = self.build_command(target)
        now = datetime.now(UTC)
        return ToolResult(
            tool_name=self.meta.name,
            command=cmd,
            started_at=now,
            finished_at=now,
            duration_seconds=0.0,
            exit_code=None,
            status=ToolResultStatus.NOT_INSTALLED,
            error_message=(
                f"{self.meta.name}: stub integration ({self.stub_status}). "
                "Implement the wrapper before running."
            ),
        )

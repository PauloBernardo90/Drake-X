"""Sandbox-specific exceptions.

All sandbox exceptions inherit from :class:`SandboxError`, which itself
inherits from :class:`drake_x.exceptions.DrakeXError`. This allows callers
to catch sandbox failures specifically or as part of the broader Drake-X
error hierarchy.

The fail-closed design means the sandbox will raise rather than silently
degrade to an unsafe execution mode.
"""

from __future__ import annotations

from ..exceptions import DrakeXError


class SandboxError(DrakeXError):
    """Base class for all sandbox errors."""


class SandboxUnavailableError(SandboxError):
    """The sandbox backend (e.g. Firejail) is not installed or not usable."""


class IsolationError(SandboxError):
    """The sandbox cannot guarantee the required level of isolation.

    This is the fail-closed exception: if the sandbox detects that it
    cannot enforce the security policy, it raises this rather than
    proceeding without isolation.
    """


class WorkspaceError(SandboxError):
    """Failed to create, populate, or clean up the ephemeral workspace."""


class SandboxTimeoutError(SandboxError):
    """The sandboxed command exceeded its timeout."""


class InvalidSampleError(SandboxError):
    """The sample path is invalid, inaccessible, or fails validation."""


class NetworkPolicyError(SandboxError):
    """Network access was requested but is not allowed by the current policy."""

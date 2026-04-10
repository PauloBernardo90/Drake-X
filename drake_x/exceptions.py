"""Drake-X exception hierarchy.

Exceptions are intentionally small and explicit so callers can distinguish
"this scan failed because the user gave us a bad target" from "the database
is broken" and react accordingly.
"""

from __future__ import annotations


class DrakeXError(Exception):
    """Base class for all Drake-X errors."""


class InvalidTargetError(DrakeXError):
    """Raised when an input target cannot be parsed or fails validation."""


class ScopeViolationError(DrakeXError):
    """Raised when a target is rejected by scope-aware validation."""


class ToolUnavailableError(DrakeXError):
    """Raised when a required tool is not installed on the host."""


class ToolExecutionError(DrakeXError):
    """Raised when a tool wrapper fails in an unexpected way.

    Routine non-zero exits are NOT this error — they are reported via
    :class:`drake_x.models.tool_result.ToolResult` instead.
    """


class NormalizationError(DrakeXError):
    """Raised when a normalizer encounters an unrecoverable schema problem."""


class StorageError(DrakeXError):
    """Raised on persistence-layer failures."""


class AIUnavailableError(DrakeXError):
    """Raised when the local Ollama runtime cannot be reached."""


class ConfigurationError(DrakeXError):
    """Raised on invalid runtime configuration."""


class WorkspaceError(DrakeXError):
    """Raised on workspace initialization or load failures."""


class ScopeFileError(DrakeXError):
    """Raised on malformed or missing engagement scope files."""


class OutOfScopeError(DrakeXError):
    """Raised when a target is rejected by the engagement scope file.

    Distinct from :class:`ScopeViolationError`, which covers per-input
    safety checks (loopback, link-local, etc). This one covers
    operator-declared engagement scope.
    """


class ConfirmationDeniedError(DrakeXError):
    """Raised when an active action is refused at the confirmation gate."""


class PluginLoadError(DrakeXError):
    """Raised when a plugin/integration cannot be loaded."""

"""Drake-X core framework primitives.

The :mod:`drake_x.core` package contains the *new* framework primitives
introduced in v0.2: workspaces, the engine, the audit log, the rate limiter,
the workspace-rooted storage layer, and the plugin loader.

The legacy v1 modules (:mod:`drake_x.orchestrator`, :mod:`drake_x.registry`,
:mod:`drake_x.session_store`) remain in place to keep the v1 CLI and tests
working. New code should depend on this package instead.
"""

from .audit import AuditEvent, AuditLog
from .plugin_loader import PluginLoader, ToolEntry
from .rate_limit import RateLimiter
from .storage import WorkspaceStorage
from .workspace import Workspace, WorkspaceConfig

__all__ = [
    "AuditEvent",
    "AuditLog",
    "PluginLoader",
    "ToolEntry",
    "RateLimiter",
    "WorkspaceStorage",
    "Workspace",
    "WorkspaceConfig",
]

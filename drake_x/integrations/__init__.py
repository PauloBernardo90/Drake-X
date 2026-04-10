"""Drake-X integrations.

This package is the v2 home for tool adapters. The seven shipped adapters
still live under :mod:`drake_x.tools` (their v1 location) — both the v1
orchestrator/tests and the v2 engine load them via the same code paths.

The :mod:`.builtin` subpackage re-exports them so future code can simply
``from drake_x.integrations.builtin import NmapTool`` and ignore the v1
location.

The :mod:`.optional` subpackage holds *stubs* for tools we plan to support
but have not implemented yet (subfinder, amass, nuclei, ffuf, ...). These
stubs declare meta + a ``build_command`` so the plugin loader and registry
recognize them, but they refuse to run unless the operator explicitly
enables them.
"""

from ..tools.base import BaseTool, ToolMeta

__all__ = ["BaseTool", "ToolMeta"]

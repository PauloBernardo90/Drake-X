"""Tool adapters for native Kali binaries.

Each adapter is a small wrapper that:

- knows the canonical binary name
- declares which profiles it participates in
- builds a safe argv list (NEVER a shell string)
- runs the process via :func:`asyncio.create_subprocess_exec`
- captures stdout / stderr / exit / duration into a
  :class:`drake_x.models.tool_result.ToolResult`

Adapters never raise on routine failures. Internal/wrapper failures (e.g. the
binary disappearing mid-run) raise :class:`drake_x.exceptions.ToolExecutionError`.
"""

from .base import BaseTool, ToolMeta
from .curl import CurlTool
from .dig import DigTool
from .nikto import NiktoTool
from .nmap import NmapTool
from .sslscan import SslscanTool
from .whatweb import WhatWebTool
from .whois import WhoisTool

ALL_TOOLS: tuple[type[BaseTool], ...] = (
    NmapTool,
    DigTool,
    WhoisTool,
    WhatWebTool,
    NiktoTool,
    CurlTool,
    SslscanTool,
)

__all__ = [
    "BaseTool",
    "ToolMeta",
    "NmapTool",
    "DigTool",
    "WhoisTool",
    "WhatWebTool",
    "NiktoTool",
    "CurlTool",
    "SslscanTool",
    "ALL_TOOLS",
]

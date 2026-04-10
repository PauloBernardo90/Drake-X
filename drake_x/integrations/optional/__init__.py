"""Optional integrations.

This package holds two kinds of integrations:

1. **Real implementations** (:data:`OPTIONAL_REAL_TOOLS`) that the
   :class:`drake_x.core.plugin_loader.PluginLoader` discovers and exposes
   to ``drake tools``, ``drake recon plan/run`` and the engine. They use
   the standard :class:`drake_x.tools.base.BaseTool` subprocess machinery
   and ``shutil.which`` so the host doesn't need to have the binary
   installed for Drake-X itself to start.
2. **Stubs** (:data:`OPTIONAL_STUBS`) that declare ``meta`` and a real
   ``build_command`` so plans and audits can reason about them, but whose
   ``run`` refuses to execute until the wrapper is implemented.

In v0.3 ``httpx`` graduated from a stub to a real integration. The
remaining tools stay as stubs and are scheduled for future passes.
"""

from .amass import AmassStub
from .dnsx import DnsxStub
from .eyewitness import EyewitnessStub
from .feroxbuster import FeroxbusterStub
from .ffuf import FfufStub, FfufTool
from .httpx import HttpxStub, HttpxTool
from .naabu import NaabuStub
from .nuclei import NucleiStub
from .subfinder import SubfinderStub
from .testssl import TestSslStub

#: Real, executable optional integrations the plugin loader picks up.
OPTIONAL_REAL_TOOLS = (HttpxTool, FfufTool)

#: Stub integrations that ship with metadata only. They never execute.
OPTIONAL_STUBS = (
    SubfinderStub,
    AmassStub,
    NaabuStub,
    DnsxStub,
    NucleiStub,
    FeroxbusterStub,
    EyewitnessStub,
    TestSslStub,
)

__all__ = [
    "HttpxTool",
    "HttpxStub",
    "FfufTool",
    "SubfinderStub",
    "AmassStub",
    "NaabuStub",
    "DnsxStub",
    "NucleiStub",
    "FfufStub",
    "FeroxbusterStub",
    "EyewitnessStub",
    "TestSslStub",
    "OPTIONAL_REAL_TOOLS",
    "OPTIONAL_STUBS",
]

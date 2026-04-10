"""Drake-X workflow modules.

A *module* is a higher-level recipe than a single integration. Where an
integration runs one tool, a module describes the *intent*: "passive recon
of a domain", "TLS posture inspection of a host", "headers audit of a
URL", and so on.

Modules map an intent to a Drake-X recon profile (and, in future, a custom
plan that goes beyond profiles). Each module declares whether it is passive
or active, what target types it supports, and a one-line description for
``drake recon list-modules``.
"""

from .api_inventory import ApiInventoryModule
from .base import Module, ModuleSpec
from .content_discovery import ContentDiscoveryModule
from .headers_audit import HeadersAuditModule
from .recon_active import ReconActiveModule
from .recon_passive import ReconPassiveModule
from .tls_inspect import TlsInspectModule
from .web_inspect import WebInspectModule

ALL_MODULES: tuple[type[Module], ...] = (
    ReconPassiveModule,
    ReconActiveModule,
    WebInspectModule,
    TlsInspectModule,
    HeadersAuditModule,
    ContentDiscoveryModule,
    ApiInventoryModule,
)


def get_module(name: str) -> Module:
    for cls in ALL_MODULES:
        if cls.spec.name == name:
            return cls()
    raise KeyError(f"unknown module: {name!r}")


__all__ = [
    "Module",
    "ModuleSpec",
    "ReconPassiveModule",
    "ReconActiveModule",
    "WebInspectModule",
    "TlsInspectModule",
    "HeadersAuditModule",
    "ContentDiscoveryModule",
    "ApiInventoryModule",
    "ALL_MODULES",
    "get_module",
]

"""HTTP security headers audit module.

Currently a thin wrapper around the existing curl integration. Future work:
parse HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy
into a dedicated artifact kind and surface them as :class:`Finding` rows
with CWE/OWASP references.
"""

from __future__ import annotations

from ..constants import PROFILE_PASSIVE, TARGET_DOMAIN, TARGET_URL
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class HeadersAuditModule(Module):
    spec = ModuleSpec(
        name="headers_audit",
        description="Check HTTP security headers (HSTS, CSP, framing, MIME).",
        profile=PROFILE_PASSIVE,
        action_policy=ActionPolicy.LIGHT_ACTIVE,
        target_types=(TARGET_DOMAIN, TARGET_URL),
        requires_confirmation=False,
        notes="Currently runs the curl integration; richer parsing in v0.3.",
    )

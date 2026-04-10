"""Web fingerprinting and inspection module."""

from __future__ import annotations

from ..constants import PROFILE_WEB_BASIC, TARGET_DOMAIN, TARGET_URL
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class WebInspectModule(Module):
    spec = ModuleSpec(
        name="web_inspect",
        description=(
            "Web stack inspection: HTTP headers, redirects, technologies, "
            "TLS posture, nikto information-only checks."
        ),
        profile=PROFILE_WEB_BASIC,
        action_policy=ActionPolicy.ACTIVE,
        target_types=(TARGET_DOMAIN, TARGET_URL),
        requires_confirmation=True,
    )

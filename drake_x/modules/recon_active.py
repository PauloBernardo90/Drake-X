"""Conservative active reconnaissance module."""

from __future__ import annotations

from ..constants import (
    PROFILE_SAFE,
    TARGET_CIDR,
    TARGET_DOMAIN,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_URL,
)
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class ReconActiveModule(Module):
    spec = ModuleSpec(
        name="recon_active",
        description=(
            "Conservative active recon: dig, whois, curl, whatweb, sslscan, nmap. "
            "Requires scope.allow_active=true and operator confirmation."
        ),
        profile=PROFILE_SAFE,
        action_policy=ActionPolicy.ACTIVE,
        target_types=(TARGET_DOMAIN, TARGET_URL, TARGET_IPV4, TARGET_IPV6, TARGET_CIDR),
        requires_confirmation=True,
        notes="Use this module after the operator has authorized active recon.",
    )

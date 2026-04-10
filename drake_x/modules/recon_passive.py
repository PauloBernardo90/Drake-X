"""Passive reconnaissance module.

Maps to the ``passive`` profile: DNS, WHOIS, single HTTP HEAD via curl. No
nmap, no nikto, no whatweb, no sslscan. Always allowed regardless of the
scope file's ``allow_active`` setting.
"""

from __future__ import annotations

from ..constants import (
    PROFILE_PASSIVE,
    TARGET_DOMAIN,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_URL,
)
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class ReconPassiveModule(Module):
    spec = ModuleSpec(
        name="recon_passive",
        description="Passive recon: DNS, WHOIS, one safe HTTP HEAD. No active scanning.",
        profile=PROFILE_PASSIVE,
        action_policy=ActionPolicy.PASSIVE,
        target_types=(TARGET_DOMAIN, TARGET_URL, TARGET_IPV4, TARGET_IPV6),
        requires_confirmation=False,
        notes="Default module for any new engagement.",
    )

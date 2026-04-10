"""TLS posture inspection module."""

from __future__ import annotations

from ..constants import PROFILE_SAFE, TARGET_DOMAIN, TARGET_URL
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class TlsInspectModule(Module):
    spec = ModuleSpec(
        name="tls_inspect",
        description="TLS protocol/cipher/certificate posture (sslscan, future testssl).",
        profile=PROFILE_SAFE,
        action_policy=ActionPolicy.LIGHT_ACTIVE,
        target_types=(TARGET_DOMAIN, TARGET_URL),
        requires_confirmation=False,
    )

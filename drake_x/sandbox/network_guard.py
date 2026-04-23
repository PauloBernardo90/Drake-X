"""Network policy enforcement for sandboxed executions.

This module validates and enforces the network access policy before
sandbox execution begins. The design is deny-by-default:

- ``NetworkPolicy.DENY``: no network access (enforced by Firejail ``net none``)
- ``NetworkPolicy.LAB``: network allowed (requires explicit opt-in)

The guard raises :class:`NetworkPolicyError` if an invalid or unsafe
network configuration is detected.
"""

from __future__ import annotations

from ..logging import get_logger
from .base import NetworkPolicy, SandboxConfig
from .exceptions import NetworkPolicyError

log = get_logger("sandbox.network_guard")


def validate_network_policy(config: SandboxConfig) -> None:
    """Validate the network policy configuration.

    Raises :class:`NetworkPolicyError` if the policy is invalid.
    Logs a warning if lab mode is enabled.
    """
    if config.network == NetworkPolicy.LAB:
        log.warning(
            "Network policy: LAB MODE enabled — sandboxed process will "
            "have network access. This is suitable ONLY for controlled "
            "lab environments with proper network isolation."
        )

    if config.network not in (NetworkPolicy.DENY, NetworkPolicy.LAB):
        raise NetworkPolicyError(
            f"Unknown network policy: {config.network!r}. "
            f"Valid options: {NetworkPolicy.DENY!r}, {NetworkPolicy.LAB!r}"
        )


def describe_network_policy(config: SandboxConfig) -> str:
    """Return a human-readable description of the network policy."""
    if config.network == NetworkPolicy.DENY:
        return "Network access DENIED (default safe mode)"
    return "Network access ALLOWED (lab mode — explicit opt-in)"

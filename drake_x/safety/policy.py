"""Active vs passive action policy.

Drake-X labels every module and integration as ``passive`` or ``active``.
Active actions go through an extra confirmation gate and are refused
outright when the scope file's ``allow_active`` flag is false.

The classifier is just a small lookup table; the heavy lifting (asking the
operator, denying out-of-scope) lives in the engine and the
:class:`ScopeEnforcer`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..models.scope import ScopeFile


class ActionPolicy(StrEnum):
    """How an action interacts with the target."""

    PASSIVE = "passive"        # never touches the target (DNS, WHOIS, OSINT)
    LIGHT_ACTIVE = "light"     # one-shot HTTP, dig over the network, sslscan
    ACTIVE = "active"          # service discovery, fingerprinting (nmap, whatweb)
    INTRUSIVE = "intrusive"    # noisier active recon (nikto, ffuf, nuclei)


# Friendly classification for the integrations Drake-X knows about. Anything
# unknown defaults to ACTIVE (conservative).
_BUILTIN_POLICY: dict[str, ActionPolicy] = {
    "whois": ActionPolicy.PASSIVE,
    "dig": ActionPolicy.LIGHT_ACTIVE,
    "curl": ActionPolicy.LIGHT_ACTIVE,
    "sslscan": ActionPolicy.LIGHT_ACTIVE,
    "whatweb": ActionPolicy.ACTIVE,
    "nmap": ActionPolicy.ACTIVE,
    "nikto": ActionPolicy.INTRUSIVE,
    # Optional integrations (stubs today; classified for the day they exist)
    "httpx": ActionPolicy.LIGHT_ACTIVE,
    "subfinder": ActionPolicy.PASSIVE,
    "amass": ActionPolicy.LIGHT_ACTIVE,
    "naabu": ActionPolicy.ACTIVE,
    "dnsx": ActionPolicy.LIGHT_ACTIVE,
    "nuclei": ActionPolicy.INTRUSIVE,
    "ffuf": ActionPolicy.INTRUSIVE,
    "feroxbuster": ActionPolicy.INTRUSIVE,
    "eyewitness": ActionPolicy.ACTIVE,
    "testssl": ActionPolicy.LIGHT_ACTIVE,
}


@dataclass(frozen=True)
class PolicyDecision:
    """Result of asking the policy classifier whether an action may run."""

    allowed: bool
    requires_confirmation: bool
    policy: ActionPolicy
    reason: str


class PolicyClassifier:
    """Map an integration name to an :class:`ActionPolicy` and decide if it can run."""

    def __init__(self, scope: ScopeFile) -> None:
        self.scope = scope

    def classify(self, integration_name: str) -> ActionPolicy:
        return _BUILTIN_POLICY.get(integration_name, ActionPolicy.ACTIVE)

    def decide(self, integration_name: str) -> PolicyDecision:
        policy = self.classify(integration_name)
        if policy == ActionPolicy.PASSIVE:
            return PolicyDecision(
                allowed=True,
                requires_confirmation=False,
                policy=policy,
                reason="passive integration — always permitted",
            )
        if policy == ActionPolicy.LIGHT_ACTIVE:
            # light-active is allowed without confirmation but blocked entirely
            # when the scope explicitly forbids active recon
            allowed = self.scope.allow_active or True  # light is always permitted
            return PolicyDecision(
                allowed=allowed,
                requires_confirmation=False,
                policy=policy,
                reason="light-active integration — permitted but worth noting in audit",
            )
        if policy == ActionPolicy.ACTIVE:
            return PolicyDecision(
                allowed=self.scope.allow_active,
                requires_confirmation=True,
                policy=policy,
                reason=(
                    "active integration — requires scope.allow_active=true and operator confirmation"
                ),
            )
        # INTRUSIVE
        return PolicyDecision(
            allowed=self.scope.allow_active,
            requires_confirmation=True,
            policy=policy,
            reason=(
                "intrusive integration — requires scope.allow_active=true and operator confirmation"
            ),
        )

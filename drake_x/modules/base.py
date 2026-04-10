"""Module base class.

Modules are intentionally thin in v0.2: each one declares a name, a
description, an :class:`ActionPolicy` label, the target types it accepts,
and the underlying Drake-X recon profile to use. The engine still selects
integrations from the plugin loader using that profile, so today a module
is essentially "a friendly name for a profile + a couple of constraints".

Future versions will let modules build *bespoke* execution plans (sequence
multiple integrations, conditionally enable steps based on previous
artifacts, etc). The interface is designed so that change can land without
breaking the CLI surface.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..safety.policy import ActionPolicy


@dataclass(frozen=True)
class ModuleSpec:
    """Static metadata about a module."""

    name: str
    description: str
    profile: str                              # the recon profile this module maps to
    action_policy: ActionPolicy
    target_types: tuple[str, ...]
    requires_confirmation: bool = False
    notes: str | None = None


class Module:
    """Abstract base. Subclasses MUST set :attr:`spec`."""

    spec: ModuleSpec

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def description(self) -> str:
        return self.spec.description

    @property
    def profile(self) -> str:
        return self.spec.profile

    @property
    def is_active(self) -> bool:
        return self.spec.action_policy in {
            ActionPolicy.ACTIVE,
            ActionPolicy.INTRUSIVE,
        }

    def supports_target_type(self, target_type: str) -> bool:
        return target_type in self.spec.target_types

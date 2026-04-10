"""API inventory module.

This module ingests an operator-supplied OpenAPI/Swagger spec file (JSON
or YAML, from local disk) and produces an ``api.inventory`` artifact
listing every endpoint, method, parameter, and authentication requirement.

No network calls are made — the operator provides the spec explicitly.
The resulting artifact can be consumed by AI tasks (classify, next-steps)
and the reporting pipeline.

Usage via CLI::

    drake api ingest /path/to/openapi.json -w my-engagement
"""

from __future__ import annotations

from ..constants import PROFILE_PASSIVE, TARGET_URL
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class ApiInventoryModule(Module):
    spec = ModuleSpec(
        name="api_inventory",
        description=(
            "Build an endpoint inventory from a local OpenAPI/Swagger spec file. "
            "No network calls — the operator supplies the spec."
        ),
        profile=PROFILE_PASSIVE,
        action_policy=ActionPolicy.PASSIVE,
        target_types=(TARGET_URL,),
        requires_confirmation=False,
        notes="Use `drake api ingest <file>` to parse a spec into an artifact.",
    )

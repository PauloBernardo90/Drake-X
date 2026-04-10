"""Engagement scope data model.

A scope file is the operator's declaration of what is in-bounds for an
engagement. It is *separate* from the per-target safety checks in
:mod:`drake_x.scope` (which reject loopback / link-local / huge CIDRs no
matter what the user says). Both layers must agree before a target is
scanned.

The model is intentionally permissive about how operators express assets:

- ``domain``         — exact host (``api.example.com``)
- ``wildcard_domain`` — anything ending in ``.example.com``
- ``ipv4`` / ``ipv6`` — single address
- ``cidr``           — IPv4 or IPv6 network
- ``url_prefix``     — exact URL prefix (``https://api.example.com/v2/``)

Out-of-scope rules win over in-scope rules. The enforcer evaluates
exclusions first.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ScopeAssetKind = Literal[
    "domain",
    "wildcard_domain",
    "ipv4",
    "ipv6",
    "cidr",
    "url_prefix",
]


class ScopeAsset(BaseModel):
    """One in-scope or out-of-scope asset declared by the operator."""

    model_config = ConfigDict(frozen=True)

    kind: ScopeAssetKind
    value: str = Field(..., description="The literal value (host, IP, CIDR, URL prefix).")
    notes: str | None = Field(default=None, description="Free-form operator note.")


class ScopeFile(BaseModel):
    """A parsed engagement scope.

    The fields are intentionally explicit so we can serialize this back to
    YAML/JSON for audit purposes without losing meaning.
    """

    model_config = ConfigDict(frozen=False)

    engagement: str = Field(..., description="Human-readable engagement name.")
    authorization_reference: str = Field(
        ...,
        description=(
            "Operator's authorization reference (PO number, HackerOne report, "
            "internal ticket, signed letter ID). Recorded for audit, not parsed."
        ),
    )
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    out_of_scope: list[ScopeAsset] = Field(default_factory=list)

    rate_limit_per_host_rps: float = Field(
        default=5.0,
        ge=0.1,
        le=200.0,
        description="Per-host request rate limit applied to integrations that honor it.",
    )
    max_concurrency: int = Field(
        default=4,
        ge=1,
        le=64,
        description="Maximum number of integrations the engine will run in parallel.",
    )
    allow_active: bool = Field(
        default=False,
        description=(
            "When false (default), active modules are refused even if the "
            "operator passes --yes on the CLI. Flip to true only after "
            "confirming the engagement permits active recon."
        ),
    )
    notes: str | None = Field(default=None)


class ScopeDecision(BaseModel):
    """Result of asking the enforcer whether a target is in scope."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str
    matched_in_scope: ScopeAsset | None = None
    matched_out_of_scope: ScopeAsset | None = None

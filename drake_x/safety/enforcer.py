"""Engagement scope enforcement.

The enforcer translates an operator-declared :class:`ScopeFile` into a
predicate over :class:`Target` objects. It evaluates exclusions before
inclusions so out-of-scope rules always win.

The enforcer is intentionally pure: it never logs, never prompts, never
mutates state. Callers (the engine, the CLI) are responsible for surfacing
its decisions.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from ..models.scope import ScopeAsset, ScopeDecision, ScopeFile
from ..models.target import Target


class ScopeEnforcer:
    """Match :class:`Target` instances against a parsed :class:`ScopeFile`."""

    def __init__(self, scope: ScopeFile) -> None:
        self.scope = scope

    # ----- public API --------------------------------------------------

    def check_target(self, target: Target) -> ScopeDecision:
        """Decide whether ``target`` is in or out of scope.

        Order of evaluation:

        1. Check the out-of-scope list. Any match → DENY.
        2. Check the in-scope list. Any match → ALLOW.
        3. No match → DENY (deny by default).
        """
        for asset in self.scope.out_of_scope:
            if self._asset_matches_target(asset, target):
                return ScopeDecision(
                    allowed=False,
                    matched_out_of_scope=asset,
                    reason=f"target matches out_of_scope rule {asset.kind}={asset.value!r}",
                )

        for asset in self.scope.in_scope:
            if self._asset_matches_target(asset, target):
                return ScopeDecision(
                    allowed=True,
                    matched_in_scope=asset,
                    reason=f"target matches in_scope rule {asset.kind}={asset.value!r}",
                )

        return ScopeDecision(
            allowed=False,
            reason=(
                "target is not declared in_scope; Drake-X denies by default. "
                "Add an in_scope rule or pass a different target."
            ),
        )

    # ----- internals ---------------------------------------------------

    @staticmethod
    def _asset_matches_target(asset: ScopeAsset, target: Target) -> bool:
        host = (target.host or "").lower()
        canonical = (target.canonical or "").lower()

        if asset.kind == "domain":
            if target.target_type in {"domain", "url"}:
                return host == asset.value.lower()
            return False

        if asset.kind == "wildcard_domain":
            if target.target_type not in {"domain", "url"}:
                return False
            base = asset.value.lower().lstrip(".")
            return host == base or host.endswith("." + base)

        if asset.kind in {"ipv4", "ipv6"}:
            try:
                target_addr = ipaddress.ip_address(host)
                rule_addr = ipaddress.ip_address(asset.value)
            except ValueError:
                return False
            return target_addr == rule_addr

        if asset.kind == "cidr":
            try:
                rule_net = ipaddress.ip_network(asset.value, strict=False)
            except ValueError:
                return False
            if target.target_type == "cidr":
                try:
                    target_net = ipaddress.ip_network(target.canonical, strict=False)
                except ValueError:
                    return False
                return target_net.subnet_of(rule_net)
            try:
                target_addr = ipaddress.ip_address(host)
            except ValueError:
                return False
            return target_addr in rule_net

        if asset.kind == "url_prefix":
            if target.target_type != "url":
                return False
            parsed_rule = urlparse(asset.value)
            parsed_target = urlparse(canonical)
            if parsed_rule.scheme != parsed_target.scheme:
                return False
            if parsed_rule.netloc.lower() != parsed_target.netloc.lower():
                return False
            return parsed_target.path.startswith(parsed_rule.path or "/")

        return False

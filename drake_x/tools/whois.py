"""whois adapter — passive registration metadata."""

from __future__ import annotations

from ..constants import (
    PROFILE_PASSIVE,
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class WhoisTool(BaseTool):
    meta = ToolMeta(
        name="whois",
        binary="whois",
        description="Passive WHOIS lookup for domains and IPs.",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE, PROFILE_WEB_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_URL, TARGET_IPV4, TARGET_IPV6),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        return [self.meta.binary, target.host]

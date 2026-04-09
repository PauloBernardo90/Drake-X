"""dig adapter — pulls common DNS record types.

Runs ``dig +noall +answer ANY <host>`` plus a couple of explicit follow-ups
because many resolvers refuse ANY queries today.
"""

from __future__ import annotations

from ..constants import (
    PROFILE_NETWORK_BASIC,
    PROFILE_PASSIVE,
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class DigTool(BaseTool):
    meta = ToolMeta(
        name="dig",
        binary="dig",
        description="DNS record lookups (A/AAAA/CNAME/MX/NS/TXT).",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE, PROFILE_WEB_BASIC, PROFILE_NETWORK_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        # Use +short across multiple types to keep parsing trivial.
        # We pack several queries into one dig invocation.
        host = target.host
        cmd = [self.meta.binary, "+nocmd", "+noall", "+answer", "+nostats", "+time=5", "+tries=2"]
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            cmd.extend([host, rtype])
        return cmd

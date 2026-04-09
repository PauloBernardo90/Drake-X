"""nmap adapter — service discovery oriented.

We deliberately avoid intrusive scripts. The defaults below are conservative:
top-1000 TCP ports, light service detection (-sV), no OS detection, no NSE
``vuln`` category. Anyone who wants more aggressive flags should add a new
profile rather than relax this one.
"""

from __future__ import annotations

from ..constants import (
    PROFILE_NETWORK_BASIC,
    PROFILE_SAFE,
    TARGET_CIDR,
    TARGET_DOMAIN,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class NmapTool(BaseTool):
    meta = ToolMeta(
        name="nmap",
        binary="nmap",
        description="TCP service discovery (top 1000 ports, light service detection).",
        profiles=(PROFILE_SAFE, PROFILE_NETWORK_BASIC),
        target_types=(TARGET_IPV4, TARGET_IPV6, TARGET_CIDR, TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=False,  # network scans serialize cleanly to keep load low
    )

    def build_command(self, target: Target) -> list[str]:
        host = target.host
        cmd: list[str] = [
            self.meta.binary,
            "-Pn",            # don't ping; many lab hosts drop ICMP
            "-sV",            # version detection
            "--open",         # only show open ports in normal output
            "-T3",            # polite-ish timing
            "--max-retries", "2",
            "-oX", "-",       # XML to stdout for stable parsing
        ]
        if target.target_type == TARGET_IPV6:
            cmd.append("-6")
        cmd.append(host)
        return cmd

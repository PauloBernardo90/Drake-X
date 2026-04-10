"""dnsx — fast DNS resolver stub."""

from __future__ import annotations

from ...constants import (
    PROFILE_PASSIVE,
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
)
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class DnsxStub(StubTool):
    meta = ToolMeta(
        name="dnsx",
        binary="dnsx",
        description="Fast DNS resolver (projectdiscovery).",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE, PROFILE_WEB_BASIC),
        target_types=(TARGET_DOMAIN,),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        return [
            self.meta.binary,
            "-silent",
            "-resp",
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-ns",
            "-txt",
            target.host,
        ]

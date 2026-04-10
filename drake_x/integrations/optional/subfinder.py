"""subfinder — passive subdomain enumeration stub."""

from __future__ import annotations

from ...constants import PROFILE_PASSIVE, PROFILE_SAFE, TARGET_DOMAIN
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class SubfinderStub(StubTool):
    meta = ToolMeta(
        name="subfinder",
        binary="subfinder",
        description="Passive subdomain enumeration (projectdiscovery).",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE),
        target_types=(TARGET_DOMAIN,),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        return [self.meta.binary, "-silent", "-d", target.host]

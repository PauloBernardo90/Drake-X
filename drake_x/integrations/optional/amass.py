"""amass — OWASP subdomain enumeration stub."""

from __future__ import annotations

from ...constants import PROFILE_PASSIVE, PROFILE_SAFE, TARGET_DOMAIN
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class AmassStub(StubTool):
    meta = ToolMeta(
        name="amass",
        binary="amass",
        description="DNS enumeration and asset discovery (OWASP amass).",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE),
        target_types=(TARGET_DOMAIN,),
        required=False,
        parallel_safe=False,
    )

    def build_command(self, target: Target) -> list[str]:
        # `enum -passive` keeps amass from generating active probes.
        return [self.meta.binary, "enum", "-passive", "-d", target.host]

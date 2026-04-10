"""naabu — fast TCP port scanner stub."""

from __future__ import annotations

from ...constants import (
    PROFILE_NETWORK_BASIC,
    PROFILE_SAFE,
    TARGET_CIDR,
    TARGET_DOMAIN,
    TARGET_IPV4,
    TARGET_IPV6,
)
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class NaabuStub(StubTool):
    meta = ToolMeta(
        name="naabu",
        binary="naabu",
        description="Fast TCP port scanner (projectdiscovery).",
        profiles=(PROFILE_SAFE, PROFILE_NETWORK_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_IPV4, TARGET_IPV6, TARGET_CIDR),
        required=False,
        parallel_safe=False,
    )

    def build_command(self, target: Target) -> list[str]:
        return [
            self.meta.binary,
            "-silent",
            "-rate",
            "100",
            "-host",
            target.host,
        ]

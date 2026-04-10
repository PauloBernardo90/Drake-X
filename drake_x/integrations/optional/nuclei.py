"""nuclei — template-based scanner stub.

Drake-X classifies nuclei as :class:`ActionPolicy.INTRUSIVE`, so even when
this stub becomes a real adapter the engine will refuse to run it without
``scope.allow_active=true`` and an explicit operator confirmation.
"""

from __future__ import annotations

from ...constants import PROFILE_WEB_BASIC, TARGET_DOMAIN, TARGET_URL
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class NucleiStub(StubTool):
    meta = ToolMeta(
        name="nuclei",
        binary="nuclei",
        description="Template-based vulnerability scanner (intrusive).",
        profiles=(PROFILE_WEB_BASIC,),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=False,
    )

    def build_command(self, target: Target) -> list[str]:
        target_str = target.canonical if target.target_type == "url" else target.host
        return [
            self.meta.binary,
            "-silent",
            "-rl",
            "5",
            "-severity",
            "info,low,medium",
            "-target",
            target_str,
        ]

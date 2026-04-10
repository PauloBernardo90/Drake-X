"""EyeWitness — screenshot/evidence collection stub."""

from __future__ import annotations

from ...constants import PROFILE_WEB_BASIC, TARGET_URL
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class EyewitnessStub(StubTool):
    meta = ToolMeta(
        name="eyewitness",
        binary="eyewitness",
        description="Headless web screenshots and metadata collection.",
        profiles=(PROFILE_WEB_BASIC,),
        target_types=(TARGET_URL,),
        required=False,
        parallel_safe=False,
    )

    def build_command(self, target: Target) -> list[str]:
        return [
            self.meta.binary,
            "--single",
            target.canonical,
            "--no-prompt",
            "--web",
        ]

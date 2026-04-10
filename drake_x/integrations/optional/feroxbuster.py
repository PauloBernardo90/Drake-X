"""feroxbuster — recursive content discovery stub (intrusive)."""

from __future__ import annotations

from ...constants import PROFILE_WEB_BASIC, TARGET_URL
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class FeroxbusterStub(StubTool):
    meta = ToolMeta(
        name="feroxbuster",
        binary="feroxbuster",
        description="Recursive content discovery (intrusive).",
        profiles=(PROFILE_WEB_BASIC,),
        target_types=(TARGET_URL,),
        required=False,
        parallel_safe=False,
    )

    def build_command(self, target: Target) -> list[str]:
        return [
            self.meta.binary,
            "--silent",
            "--depth",
            "2",
            "--threads",
            "10",
            "-u",
            target.canonical,
        ]

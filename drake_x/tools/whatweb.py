"""whatweb adapter — web technology fingerprinting."""

from __future__ import annotations

from ..constants import (
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class WhatWebTool(BaseTool):
    meta = ToolMeta(
        name="whatweb",
        binary="whatweb",
        description="HTTP fingerprinting (technologies, frameworks, headers).",
        profiles=(PROFILE_SAFE, PROFILE_WEB_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        # Stick to aggression level 1 (light) and JSON output for parsing.
        # Default user-agent is fine; we don't try to evade WAFs.
        url = target.canonical if target.target_type == "url" else f"http://{target.host}"
        return [
            self.meta.binary,
            "-a", "1",
            "--no-errors",
            "--log-json=-",
            url,
        ]

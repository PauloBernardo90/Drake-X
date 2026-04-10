"""curl adapter — single HEAD/GET to inspect headers and redirects."""

from __future__ import annotations

from ..constants import (
    PROFILE_PASSIVE,
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class CurlTool(BaseTool):
    meta = ToolMeta(
        name="curl",
        binary="curl",
        description="Single HTTP request to inspect headers, status, redirects.",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE, PROFILE_WEB_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=True,
        http_style=True,
    )

    def build_command(self, target: Target) -> list[str]:
        if target.target_type == "url":
            url = target.canonical
        else:
            url = f"http://{target.host}"
        return [
            self.meta.binary,
            "-sS",
            "-I",                              # HEAD
            "-L",                              # follow redirects
            "--max-time", "20",
            "--max-redirs", "5",
            "-A", "Drake-X-Recon/0.1 (+local)",
            url,
        ]

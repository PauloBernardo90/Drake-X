"""ffuf — content discovery integration (intrusive).

Drake-X classifies ffuf as :class:`ActionPolicy.INTRUSIVE`, meaning the
engine refuses to run it unless ``scope.allow_active=true`` AND the
operator confirms at the gate. Even then, the wrapper enforces a rate
limit (``-rate 20`` by default), filters to safe status codes, and uses
``-json`` output for deterministic parsing.

The default wordlist is ``/usr/share/wordlists/dirb/common.txt`` (shipped
with Kali). Operators can override it by setting the
``DRAKE_X_FFUF_WORDLIST`` environment variable. If the wordlist file does
not exist at runtime, the tool returns ``NOT_INSTALLED`` with a clear
error message rather than silently crashing ffuf.
"""

from __future__ import annotations

import os
from pathlib import Path

from ...constants import PROFILE_WEB_BASIC, TARGET_DOMAIN, TARGET_URL
from ...models.target import Target
from ...models.tool_result import ToolResult, ToolResultStatus
from ...tools.base import BaseTool, ToolMeta
from ...utils.timefmt import utcnow

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FfufTool(BaseTool):
    """Real ffuf wrapper for directory / content discovery."""

    meta = ToolMeta(
        name="ffuf",
        binary="ffuf",
        description="Content discovery via directory fuzzing (intrusive).",
        profiles=(PROFILE_WEB_BASIC,),
        target_types=(TARGET_URL, TARGET_DOMAIN),
        required=False,
        parallel_safe=False,
        http_style=True,
    )

    @property
    def wordlist(self) -> str:
        return os.environ.get("DRAKE_X_FFUF_WORDLIST", DEFAULT_WORDLIST)

    def build_command(self, target: Target) -> list[str]:
        if target.target_type == "url":
            base_url = target.canonical.rstrip("/")
        else:
            base_url = f"https://{target.host}"

        return [
            self.meta.binary,
            "-u", f"{base_url}/FUZZ",
            "-w", self.wordlist,
            "-mc", "200,204,301,302,307,401,403",
            "-rate", "20",
            "-t", "5",                       # threads — keep noise down
            "-recursion-depth", "0",         # no recursive follow for safety
            "-timeout", "10",
            "-json",                         # one JSON object per result line
            "-s",                            # silent — no interactive progress
        ]

    async def run(self, target: Target, *, timeout: int | None = None) -> ToolResult:
        """Override to pre-check the wordlist before launching ffuf."""
        wl = Path(self.wordlist)
        if not wl.exists():
            now = utcnow()
            return ToolResult(
                tool_name=self.meta.name,
                command=self.build_command(target),
                started_at=now,
                finished_at=now,
                duration_seconds=0.0,
                exit_code=None,
                status=ToolResultStatus.NOT_INSTALLED,
                error_message=(
                    f"wordlist not found: {wl}. "
                    "Set DRAKE_X_FFUF_WORDLIST to override, or install a Kali wordlist package."
                ),
            )
        return await super().run(target, timeout=timeout)


# Backward-compat alias
FfufStub = FfufTool

__all__ = ["FfufTool", "FfufStub"]

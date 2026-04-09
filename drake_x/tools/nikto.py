"""nikto adapter — high-level web server checks.

Drake-X uses nikto only in the ``web-basic`` profile because it generates
fairly noisy traffic. We always pass ``-Tuning x`` to disable the most
intrusive plugin categories and rely on parser logic to extract only
high-level findings, never exploit hints.
"""

from __future__ import annotations

from ..constants import (
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class NiktoTool(BaseTool):
    meta = ToolMeta(
        name="nikto",
        binary="nikto",
        description="Light web server posture checks (information-only).",
        profiles=(PROFILE_WEB_BASIC,),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=False,
    )

    def build_command(self, target: Target) -> list[str]:
        host = target.canonical if target.target_type == "url" else target.host
        # -Tuning x disables intrusive checks (SQLi, command injection, etc).
        # We use 'b' (software identification) and 'g' (generic) which are
        # informational categories.
        return [
            self.meta.binary,
            "-host", host,
            "-Tuning", "bg",
            "-ask", "no",
            "-maxtime", "120",
            "-Format", "txt",
            "-output", "-",
        ]

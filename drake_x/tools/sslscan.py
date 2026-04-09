"""sslscan adapter — TLS protocol/cipher/cert summary."""

from __future__ import annotations

from ..constants import (
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ..models.target import Target
from .base import BaseTool, ToolMeta


class SslscanTool(BaseTool):
    meta = ToolMeta(
        name="sslscan",
        binary="sslscan",
        description="Enumerate TLS protocols, ciphers, and certificate metadata.",
        profiles=(PROFILE_SAFE, PROFILE_WEB_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        host = target.host
        port = 443
        if target.target_type == "url" and target.url_port:
            port = target.url_port
        return [
            self.meta.binary,
            "--no-colour",
            "--show-certificate",
            f"{host}:{port}",
        ]

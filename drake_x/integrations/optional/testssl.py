"""testssl.sh — TLS auditing stub."""

from __future__ import annotations

from ...constants import (
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ...models.target import Target
from ...tools.base import ToolMeta
from ._stub import StubTool


class TestSslStub(StubTool):
    meta = ToolMeta(
        name="testssl",
        binary="testssl.sh",
        description="Comprehensive TLS configuration auditor (testssl.sh).",
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
            "--quiet",
            "--color",
            "0",
            "--severity",
            "LOW",
            "--jsonfile-pretty",
            "-",
            f"{host}:{port}",
        ]

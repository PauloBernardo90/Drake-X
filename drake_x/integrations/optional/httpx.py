"""httpx (projectdiscovery) — HTTP probe integration.

Drake-X v0.3 promotes httpx from a stub to a real :class:`BaseTool`
subclass. The wrapper:

- detects the binary via ``shutil.which`` (inherited from :class:`BaseTool`)
- builds a deterministic argv list (no shell injection)
- runs httpx with ``-json`` so the output is one JSON object per target
- enables ``-include-response-header`` so the headers normalizer in
  :mod:`drake_x.normalize.headers` can audit security controls without a
  second curl pass
- preserves raw stdout in the resulting :class:`ToolResult` for evidence
  purposes

The companion normalizer lives at :mod:`drake_x.normalize.httpx` and
produces an :class:`Artifact` of kind ``web.http_probe``.

Note on profiles: httpx makes a real GET request, which is heavier than
the curl HEAD that ``recon_passive`` already runs. We deliberately do
NOT include httpx in ``PROFILE_PASSIVE`` — it lives in ``PROFILE_SAFE``
and ``PROFILE_WEB_BASIC`` only.
"""

from __future__ import annotations

from ...constants import (
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    TARGET_DOMAIN,
    TARGET_URL,
)
from ...models.target import Target
from ...tools.base import BaseTool, ToolMeta


class HttpxTool(BaseTool):
    """Real ProjectDiscovery httpx wrapper."""

    meta = ToolMeta(
        name="httpx",
        binary="httpx",
        description="HTTP probing, headers, and host fingerprinting (projectdiscovery).",
        profiles=(PROFILE_SAFE, PROFILE_WEB_BASIC),
        target_types=(TARGET_DOMAIN, TARGET_URL),
        required=False,
        parallel_safe=True,
        http_style=True,
    )

    def build_command(self, target: Target) -> list[str]:
        """Build the httpx argv for ``target``.

        Domains are probed over HTTPS by default. URL targets keep the
        operator's chosen scheme/path/port.
        """
        if target.target_type == "url":
            url = target.canonical
        else:
            url = f"https://{target.host}"

        return [
            self.meta.binary,
            "-silent",                       # no progress noise on stderr
            "-json",                         # one JSON object per target
            "-no-color",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-length",
            "-location",
            "-include-response-header",      # populate the `header` field for auditing
            "-follow-redirects",
            "-timeout", "30",
            "-u", url,
        ]


# Backwards-compatible alias so any code (or test) that imports the old
# stub name still works during the v0.2 → v0.3 transition.
HttpxStub = HttpxTool


__all__ = ["HttpxTool", "HttpxStub"]

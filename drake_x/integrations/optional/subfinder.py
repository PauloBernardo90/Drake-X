"""subfinder — passive subdomain enumeration integration.

This wrapper graduates subfinder from the v0.3 stub to a real
:class:`BaseTool` subclass. The wrapper:

- detects the binary via ``shutil.which`` (inherited from :class:`BaseTool`)
- builds a deterministic argv list (no shell injection)
- runs subfinder with ``-silent`` so stdout contains one FQDN per line
  and no progress/banner noise

subfinder is classified as :class:`ActionPolicy.PASSIVE` — it never
touches the target; it only queries third-party passive DNS and OSINT
sources. The companion normalizer lives at
:mod:`drake_x.normalize.subfinder` and produces an :class:`Artifact` of
kind ``dns.subdomains``.
"""

from __future__ import annotations

from ...constants import PROFILE_PASSIVE, PROFILE_SAFE, TARGET_DOMAIN
from ...models.target import Target
from ...tools.base import BaseTool, ToolMeta


class SubfinderTool(BaseTool):
    """Real ProjectDiscovery subfinder wrapper (passive)."""

    meta = ToolMeta(
        name="subfinder",
        binary="subfinder",
        description="Passive subdomain enumeration (projectdiscovery).",
        profiles=(PROFILE_PASSIVE, PROFILE_SAFE),
        target_types=(TARGET_DOMAIN,),
        required=False,
        parallel_safe=True,
    )

    def build_command(self, target: Target) -> list[str]:
        return [
            self.meta.binary,
            "-silent",          # one FQDN per line on stdout, no banner
            "-no-color",
            "-d", target.host,
        ]


# Backwards-compatible alias so any code (or test) that imports the old
# stub name still works during the promotion transition.
SubfinderStub = SubfinderTool


__all__ = ["SubfinderTool", "SubfinderStub"]

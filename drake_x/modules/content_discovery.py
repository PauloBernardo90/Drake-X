"""Content discovery module.

Runs ffuf (or, in future, feroxbuster) against a URL target to discover
hidden directories and files. This is classified as
:class:`ActionPolicy.INTRUSIVE`:

- The engine refuses to run it unless ``scope.allow_active=true``.
- The operator must confirm at the gate (or pass ``--yes``).
- The ffuf integration enforces its own rate limit (``-rate 20``) and
  low thread count (``-t 5``) on top of the engine's rate limiter.
- The default wordlist is ``/usr/share/wordlists/dirb/common.txt``;
  override via ``DRAKE_X_FFUF_WORDLIST``.

The module maps to the ``web-basic`` profile, which also picks up
whatweb, nikto, sslscan, curl, httpx, and dig.
"""

from __future__ import annotations

from ..constants import PROFILE_WEB_BASIC, TARGET_DOMAIN, TARGET_URL
from ..safety.policy import ActionPolicy
from .base import Module, ModuleSpec


class ContentDiscoveryModule(Module):
    spec = ModuleSpec(
        name="content_discovery",
        description=(
            "Directory and content discovery via ffuf (intrusive). "
            "Requires allow_active=true, operator confirmation, and a wordlist."
        ),
        profile=PROFILE_WEB_BASIC,
        action_policy=ActionPolicy.INTRUSIVE,
        target_types=(TARGET_URL, TARGET_DOMAIN),
        requires_confirmation=True,
        notes=(
            "Default wordlist: /usr/share/wordlists/dirb/common.txt. "
            "Override with DRAKE_X_FFUF_WORDLIST."
        ),
    )

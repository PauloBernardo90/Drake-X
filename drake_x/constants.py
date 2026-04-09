"""Project-wide constants.

Kept deliberately small. Anything user-tunable lives in :mod:`drake_x.config`
instead.
"""

from __future__ import annotations

from typing import Final

APP_NAME: Final[str] = "drake-x"
APP_DISPLAY_NAME: Final[str] = "Drake-X"

# Recon profiles. Order matters: lower index = more conservative.
PROFILE_PASSIVE: Final[str] = "passive"
PROFILE_SAFE: Final[str] = "safe"
PROFILE_WEB_BASIC: Final[str] = "web-basic"
PROFILE_NETWORK_BASIC: Final[str] = "network-basic"

ALL_PROFILES: Final[tuple[str, ...]] = (
    PROFILE_PASSIVE,
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
    PROFILE_NETWORK_BASIC,
)

DEFAULT_PROFILE: Final[str] = PROFILE_SAFE

# Target type discriminators.
TARGET_IPV4: Final[str] = "ipv4"
TARGET_IPV6: Final[str] = "ipv6"
TARGET_CIDR: Final[str] = "cidr"
TARGET_DOMAIN: Final[str] = "domain"
TARGET_URL: Final[str] = "url"

ALL_TARGET_TYPES: Final[tuple[str, ...]] = (
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_CIDR,
    TARGET_DOMAIN,
    TARGET_URL,
)

# Defaults.
DEFAULT_DB_PATH: Final[str] = "./drake_x.db"
DEFAULT_OUTPUT_DIR: Final[str] = "./drake_x_runs"
DEFAULT_OLLAMA_URL: Final[str] = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL: Final[str] = "llama3.2:3b"
DEFAULT_TIMEOUT_SECONDS: Final[int] = 180

# Authorized-use disclaimer rendered in CLI help and reports.
AUTHORIZED_USE_NOTICE: Final[str] = (
    "Drake-X is intended for AUTHORIZED security testing only. "
    "Only run it against assets you own or have explicit, written permission "
    "to assess. Unauthorized scanning may be illegal in your jurisdiction."
)

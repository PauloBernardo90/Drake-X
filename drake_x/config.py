"""Runtime configuration for Drake-X.

Configuration precedence (lowest to highest):

1. Hard-coded defaults in :mod:`drake_x.constants`.
2. Environment variables (`DRAKE_X_*`).
3. Explicit overrides passed in code (e.g. CLI flags).

We deliberately keep this very small. Anything more elaborate (TOML files,
profiles, etc.) can come later without breaking callers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from .constants import (
    ALL_PROFILES,
    DEFAULT_DB_PATH,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PROFILE,
    DEFAULT_TIMEOUT_SECONDS,
)
from .exceptions import ConfigurationError


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class DrakeXConfig:
    """Immutable configuration object passed around the application."""

    db_path: Path
    output_dir: Path
    ollama_url: str
    ollama_model: str
    default_timeout: int
    default_profile: str
    disable_ai: bool = False
    verbose: bool = False

    def with_overrides(self, **overrides: object) -> DrakeXConfig:
        """Return a copy with the given fields replaced."""
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **clean)  # type: ignore[arg-type]

    def ensure_directories(self) -> None:
        """Make sure runtime directories exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # SQLite parent dir.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


def load_config() -> DrakeXConfig:
    """Build a :class:`DrakeXConfig` from environment + defaults."""

    profile = _env("DRAKE_X_PROFILE", DEFAULT_PROFILE) or DEFAULT_PROFILE
    if profile not in ALL_PROFILES:
        raise ConfigurationError(
            f"Invalid DRAKE_X_PROFILE={profile!r}. Choose one of: {', '.join(ALL_PROFILES)}"
        )

    return DrakeXConfig(
        db_path=Path(_env("DRAKE_X_DB_PATH", DEFAULT_DB_PATH) or DEFAULT_DB_PATH).expanduser(),
        output_dir=Path(_env("DRAKE_X_OUTPUT_DIR", DEFAULT_OUTPUT_DIR) or DEFAULT_OUTPUT_DIR).expanduser(),
        ollama_url=_env("DRAKE_X_OLLAMA_URL", DEFAULT_OLLAMA_URL) or DEFAULT_OLLAMA_URL,
        ollama_model=_env("DRAKE_X_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL) or DEFAULT_OLLAMA_MODEL,
        default_timeout=_env_int("DRAKE_X_TIMEOUT", DEFAULT_TIMEOUT_SECONDS),
        default_profile=profile,
        disable_ai=_env_bool("DRAKE_X_DISABLE_AI", False),
    )


# Convenience for places that just need defaults without environment lookups.
DEFAULT_CONFIG: DrakeXConfig = DrakeXConfig(
    db_path=Path(DEFAULT_DB_PATH),
    output_dir=Path(DEFAULT_OUTPUT_DIR),
    ollama_url=DEFAULT_OLLAMA_URL,
    ollama_model=DEFAULT_OLLAMA_MODEL,
    default_timeout=DEFAULT_TIMEOUT_SECONDS,
    default_profile=DEFAULT_PROFILE,
)


__all__ = ["DrakeXConfig", "load_config", "DEFAULT_CONFIG"]

# Avoid linter complaints about unused field import in some setups.
_ = field

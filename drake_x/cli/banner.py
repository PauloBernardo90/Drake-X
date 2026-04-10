"""Startup banner for the Drake-X CLI.

The banner is loaded from ``drake_x/assets/banner.txt`` — a project-
relative path resolved via ``__file__`` so it works in both editable
installs and packaged distributions.

Display rules:

- The full ASCII art is shown only when stdout is a TTY **and** the
  terminal is at least :data:`BANNER_MIN_WIDTH` columns wide.
- On narrower terminals, the compact branded panel
  (:func:`drake_x.cli_theme.render_header`) is shown instead.
- On non-TTY output (piped, redirected, CI) the banner is suppressed
  entirely to keep machine-parseable output clean.

The module is deliberately small and self-contained. It catches every
exception internally so a missing or corrupt banner file never crashes
the CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

from .. import __version__
from ..cli_theme import render_header
from ..logging import get_logger

log = get_logger("banner")

#: Minimum terminal width (columns) required to render the full ASCII art
#: without wrapping. Below this threshold we fall back to the compact panel.
BANNER_MIN_WIDTH: int = 172

#: Resolved path to the banner file shipped inside the package.
_BANNER_PATH: Path = Path(__file__).resolve().parents[1] / "assets" / "banner.txt"


def load_banner_text() -> str | None:
    """Read the banner file from disk.

    Returns the text content, or ``None`` if the file is missing or
    unreadable.
    """
    try:
        if _BANNER_PATH.exists():
            return _BANNER_PATH.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 — banner is cosmetic; never crash
        log.debug("failed to read banner file %s: %s", _BANNER_PATH, exc)
    return None


def render_banner(console: Console) -> None:
    """Print the startup banner to ``console``.

    Chooses between the full ASCII art, the compact branded panel, or
    nothing at all depending on the terminal capabilities.
    """
    if not sys.stdout.isatty():
        return

    banner_text = load_banner_text()
    if banner_text and console.width >= BANNER_MIN_WIDTH:
        # Render in the brand accent color so it matches the CLI theme.
        console.print(f"[bright_cyan]{banner_text}[/bright_cyan]", highlight=False)
    else:
        # Narrow terminal or missing file — compact panel.
        render_header(console, version=__version__)

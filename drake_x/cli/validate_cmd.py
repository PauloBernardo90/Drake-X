"""``drake validate`` — structured validation plans (v1.0). Shell only."""
from __future__ import annotations

import typer

app = typer.Typer(no_args_is_help=True, help="Structured validation plans for multi-domain analyses.")

from ._validate_body import register  # noqa: E402

register(app)

"""``drake ingest`` — external evidence ingestion (v1.0). See Phase 2 module body."""
# Real implementation in drake_x.integrations.ingest; this module is the CLI shell.
from __future__ import annotations

import typer

app = typer.Typer(no_args_is_help=True, help="Ingest external evidence into the workspace.")

# The `evidence` subcommand is registered in the body below once the
# package ingest module is importable.
from ._ingest_body import register  # noqa: E402

register(app)

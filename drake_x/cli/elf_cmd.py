"""``drake elf`` — ELF static analysis (v1.0). Shell only."""
from __future__ import annotations

import typer

app = typer.Typer(no_args_is_help=True, help="ELF static analysis (Linux / IoT native binaries).")

from ._elf_body import register  # noqa: E402

register(app)

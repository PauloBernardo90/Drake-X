"""Drake-X CLI package.

The sole public entry point is :data:`app`, a Typer application exposed
via the ``drake`` console script. Subcommands live in their own modules
(``init_cmd``, ``scope_cmd``, ``recon_cmd``, etc.) and are registered in
:mod:`drake_x.cli.v2`.
"""

from .v2 import app

__all__ = ["app"]

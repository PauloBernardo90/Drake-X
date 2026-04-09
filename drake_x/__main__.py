"""Module entrypoint so `python -m drake_x` works identically to `drake-x`.

This exists as a robust fallback for environments where the installed console
script is not available — for example when Drake-X has been imported from a
source checkout via PYTHONPATH rather than `pip install`.
"""

from .cli import app

if __name__ == "__main__":  # pragma: no cover
    app()

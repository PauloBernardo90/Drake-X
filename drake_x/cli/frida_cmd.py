"""``drake frida`` — Frida observation template generation."""

from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success

app = typer.Typer(no_args_is_help=True, help="Frida observation script templates (NOT bypass tools).")

_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates" / "frida"

_AVAILABLE = {
    "java-method-watch": "java_method_watch.js",
    "ssl-observe": "ssl_observe.js",
    "anti-analysis-observe": "anti_analysis_observe.js",
    "jni-load-observe": "jni_load_observe.js",
    "webview-observe": "webview_observe.js",
    "packageinstaller-observe": "packageinstaller_observe.js",
}


@app.command("template")
def template(
    template_type: str = typer.Argument(..., help=f"Template type: {', '.join(sorted(_AVAILABLE))}"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path."),
) -> None:
    """Generate a Frida observation script template.

    These are OBSERVATION templates. They do NOT bypass protections.
    """
    console = make_console()

    if template_type not in _AVAILABLE:
        error(console, f"unknown template: {template_type!r}. Available: {', '.join(sorted(_AVAILABLE))}")
        raise typer.Exit(code=2)

    src = _TEMPLATES_DIR / _AVAILABLE[template_type]
    if not src.exists():
        error(console, f"template file missing: {src}")
        raise typer.Exit(code=1)

    content = src.read_text(encoding="utf-8")

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        success(console, f"template written to [accent]{output}[/accent]")
    else:
        typer.echo(content)

    info(console, "this is an OBSERVATION template — it does NOT modify app behavior.")


@app.command("list")
def list_templates() -> None:
    """List available Frida observation templates."""
    console = make_console()
    for name in sorted(_AVAILABLE):
        console.print(f"  [accent]{name}[/accent]")

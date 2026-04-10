"""``drake flow`` — interactive menu-based navigation.

A lightweight terminal menu that routes the operator to the right
Drake-X command without memorizing subcommand names. No curses, no
heavy UI — just numbered choices and stdin.

Every menu selection dispatches to an existing command. Flow does not
implement any logic itself.
"""

from __future__ import annotations

import sys

import typer

from ..cli_theme import info, make_console, success, warn

app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
    help="Interactive menu-based navigation for Drake-X.",
)

_MAIN_MENU = [
    ("Workspace Setup", "drake init <name>"),
    ("Scope Management", "drake scope validate / show / check"),
    ("Reconnaissance", "drake recon run <target> -m <module>"),
    ("Web Analysis", "drake web inspect <url>"),
    ("APK Analysis", "drake apk analyze <file.apk>"),
    ("Mission Workflow", "drake mission run <type> <target>"),
    ("AI Assist", "drake assist start <domain> <target>"),
    ("Findings", "drake findings list"),
    ("Evidence Graph", "drake graph show <session-id>"),
    ("AI Tasks", "drake ai summarize / classify / dedupe"),
    ("Reports", "drake report generate <session-id>"),
    ("Tools", "drake tools"),
]


@app.callback(invoke_without_command=True)
def flow() -> None:
    """Start interactive Drake-X flow navigation."""
    console = make_console()

    console.print()
    console.print("[brand]  Drake-X Flow Navigation[/brand]")
    console.print("  [muted]Select a category to see the command to run.[/muted]")
    console.print("  [muted]Type a number, or q to exit.[/muted]")

    while True:
        console.print()
        for i, (label, _) in enumerate(_MAIN_MENU, 1):
            console.print(f"  [accent]{i:2d}[/accent]  {label}")
        console.print(f"  [accent] q[/accent]  Exit")
        console.print()

        try:
            sys.stdout.write("  > ")
            sys.stdout.flush()
            choice = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in {"q", "quit", "exit", ""}:
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(_MAIN_MENU):
                label, command = _MAIN_MENU[idx]
                console.print()
                console.print(f"  [label]{label}[/label]")
                console.print(f"  [accent]{command}[/accent]")
                console.print()
                info(console, "copy and run the command above, or press Enter to continue.")
            else:
                warn(console, f"invalid choice: {choice}")
        except ValueError:
            warn(console, f"invalid input: {choice!r}")

    console.print()
    success(console, "flow navigation ended.")

"""``drake console`` — persistent investigation console.

Provides an interactive REPL that maintains workspace and session
context across commands, renders the banner once, and dispatches
to existing Drake-X CLI logic without duplicating it.
"""

from __future__ import annotations

import shlex
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console

from .. import __version__
from ..cli_theme import make_console, render_header
from ..core.state import ConsoleState, load_state, save_state
from ..core.workspace import Workspace, default_workspaces_root
from ..logging import get_logger

log = get_logger("console")

app = typer.Typer(no_args_is_help=False, invoke_without_command=True, help="Persistent investigation console.")


# ---------------------------------------------------------------------------
# Console REPL
# ---------------------------------------------------------------------------


class InvestigationConsole:
    """Interactive investigation REPL with persistent context."""

    def __init__(self) -> None:
        self.console: Console = make_console()
        self.state: ConsoleState = load_state()
        self._workspace: Workspace | None = None
        self._running = True

    # --- context ---

    @property
    def workspace_name(self) -> str:
        return self.state.current_workspace or ""

    @property
    def session_id(self) -> str:
        return self.state.current_session or ""

    @property
    def prompt(self) -> str:
        ws = self.workspace_name
        sid = self.state.current_session
        if ws and sid:
            return f"drake({ws}:{sid[:12]})> "
        elif ws:
            return f"drake({ws})> "
        return "drake> "

    def _resolve_workspace(self) -> Workspace | None:
        if self._workspace and self._workspace.name == self.workspace_name:
            return self._workspace
        if not self.workspace_name:
            return None
        try:
            self._workspace = Workspace.load(self.workspace_name)
            return self._workspace
        except Exception:
            self._workspace = None
            return None

    # --- banner ---

    def _render_banner(self) -> None:
        from .banner import load_banner_text, _normalize_banner_lines, BANNER_MIN_WIDTH

        width = shutil.get_terminal_size().columns
        banner_text = load_banner_text()

        if banner_text and width >= BANNER_MIN_WIDTH:
            lines = _normalize_banner_lines(banner_text)
            for line in lines:
                centered = line.center(width)
                self.console.print(f"[bright_cyan]{centered}[/bright_cyan]", highlight=False)
        elif banner_text and width >= 100:
            # Medium: try a compact version of the banner
            render_header(self.console, version=__version__)
        else:
            render_header(self.console, version=__version__)

        footer = f"v{__version__}  ·  evidence-driven malware analysis  ·  operator-controlled"
        self.console.print(f"[muted]{footer.center(width)}[/muted]")
        self.console.print()

        # Show current context
        if self.workspace_name:
            self.console.print(f"  [accent]workspace:[/accent] {self.workspace_name}")
        if self.session_id:
            self.console.print(f"  [accent]session:[/accent]   {self.session_id}")
        if not self.workspace_name:
            self.console.print("  [muted]no workspace active — use 'workspace use <name>' or 'workspace new <name>'[/muted]")
        self.console.print()

    # --- REPL ---

    def run(self) -> None:
        self._render_banner()

        while self._running:
            try:
                line = input(self.prompt).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[muted]exiting console[/muted]")
                break

            if not line:
                continue

            parts = shlex.split(line)
            cmd = parts[0].lower()
            args = parts[1:]

            handler = self._COMMANDS.get(cmd)
            if handler:
                try:
                    handler(self, args)
                except Exception as exc:
                    self.console.print(f"[danger]error: {exc}[/danger]")
            else:
                self._dispatch_drake(parts)

    # --- internal commands ---

    def _cmd_exit(self, args: list[str]) -> None:
        save_state(self.state)
        self.console.print("[muted]state saved — goodbye[/muted]")
        self._running = False

    def _cmd_help(self, args: list[str]) -> None:
        self.console.print()
        self.console.print("[bold]Console Commands:[/bold]")
        self.console.print()
        self.console.print("  [accent]workspace list[/accent]          list available workspaces")
        self.console.print("  [accent]workspace use <name>[/accent]    switch to workspace")
        self.console.print("  [accent]workspace show[/accent]          show active workspace details")
        self.console.print("  [accent]workspace new <name>[/accent]    create and switch to new workspace")
        self.console.print("  [accent]session list[/accent]            list sessions in active workspace")
        self.console.print("  [accent]session use <id>[/accent]        switch to session")
        self.console.print("  [accent]session show[/accent]            show active session details")
        self.console.print("  [accent]status[/accent]                  show current context and tool availability")
        self.console.print("  [accent]tools[/accent]                   list available tools")
        self.console.print("  [accent]help[/accent]                    show this help")
        self.console.print("  [accent]exit[/accent]                    save state and exit")
        self.console.print()
        self.console.print("[bold]Analysis Commands (dispatched with active context):[/bold]")
        self.console.print()
        self.console.print("  [accent]apk analyze <file>[/accent]      run APK analysis")
        self.console.print("  [accent]pe analyze <file>[/accent]       run PE analysis")
        self.console.print("  [accent]findings list[/accent]           list findings for active session")
        self.console.print("  [accent]report generate <sid>[/accent]   generate report")
        self.console.print("  [accent]ai summarize[/accent]            AI-assisted summary")
        self.console.print()

    def _cmd_status(self, args: list[str]) -> None:
        self.console.print()
        self.console.print(f"  [accent]workspace:[/accent]  {self.workspace_name or '[muted]none[/muted]'}")
        self.console.print(f"  [accent]session:[/accent]    {self.session_id or '[muted]none[/muted]'}")
        self.console.print(f"  [accent]last sample:[/accent] {self.state.last_sample_path or '[muted]none[/muted]'}")
        self.console.print(f"  [accent]last run dir:[/accent] {self.state.last_run_dir or '[muted]none[/muted]'}")

        ws = self._resolve_workspace()
        if ws:
            self.console.print(f"  [accent]workspace path:[/accent] {ws.root}")
            self.console.print(f"  [accent]database:[/accent] {ws.db_path}")
        self.console.print()

    def _cmd_tools(self, args: list[str]) -> None:
        self._dispatch_drake(["tools"])

    def _cmd_workspace(self, args: list[str]) -> None:
        if not args:
            self.console.print("[muted]usage: workspace list|use|show|new[/muted]")
            return

        sub = args[0].lower()

        if sub == "list":
            root = default_workspaces_root()
            if root.exists():
                dirs = sorted(d.name for d in root.iterdir() if d.is_dir() and (d / "workspace.toml").exists())
                if dirs:
                    for d in dirs:
                        marker = " [accent]<- active[/accent]" if d == self.workspace_name else ""
                        self.console.print(f"  {d}{marker}")
                else:
                    self.console.print("  [muted]no workspaces found[/muted]")
            else:
                self.console.print("  [muted]no workspaces directory[/muted]")

        elif sub == "use" and len(args) >= 2:
            name = args[1]
            try:
                ws = Workspace.load(name)
                self.state.current_workspace = ws.name
                self.state.current_session = ""
                self._workspace = ws
                save_state(self.state)
                self.console.print(f"  [ok]switched to workspace: {ws.name}[/ok]")
            except Exception as exc:
                self.console.print(f"  [danger]failed to load workspace '{name}': {exc}[/danger]")

        elif sub == "show":
            ws = self._resolve_workspace()
            if ws:
                self.console.print(f"  [accent]name:[/accent]     {ws.name}")
                self.console.print(f"  [accent]root:[/accent]     {ws.root}")
                self.console.print(f"  [accent]database:[/accent] {ws.db_path}")
                self.console.print(f"  [accent]scope:[/accent]    {ws.scope_path}")
                self.console.print(f"  [accent]runs:[/accent]     {ws.runs_dir}")
            else:
                self.console.print("  [muted]no active workspace[/muted]")

        elif sub == "new" and len(args) >= 2:
            name = args[1]
            try:
                ws = Workspace.init(name)
                self.state.current_workspace = ws.name
                self.state.current_session = ""
                self._workspace = ws
                save_state(self.state)
                self.console.print(f"  [ok]created and switched to workspace: {ws.name}[/ok]")
            except Exception as exc:
                self.console.print(f"  [danger]failed to create workspace '{name}': {exc}[/danger]")

        else:
            self.console.print("[muted]usage: workspace list|use <name>|show|new <name>[/muted]")

    def _cmd_session(self, args: list[str]) -> None:
        if not args:
            self.console.print("[muted]usage: session list|use|show[/muted]")
            return

        sub = args[0].lower()
        ws = self._resolve_workspace()

        if not ws:
            self.console.print("  [danger]no active workspace — use 'workspace use <name>' first[/danger]")
            return

        if sub == "list":
            try:
                from ..core.storage import WorkspaceStorage
                storage = WorkspaceStorage(ws.db_path)
                sessions = storage.legacy.list_sessions(limit=20)
                if sessions:
                    for s in sessions:
                        marker = " [accent]<- active[/accent]" if s.id == self.session_id else ""
                        ts = s.started_at.isoformat(timespec="seconds") if s.started_at else ""
                        self.console.print(
                            f"  [accent]{s.id}[/accent]  {ts}  "
                            f"{s.target.canonical}  [muted]({s.profile} / {s.status.value})[/muted]{marker}"
                        )
                else:
                    self.console.print("  [muted]no sessions in this workspace[/muted]")
            except Exception as exc:
                self.console.print(f"  [danger]failed to list sessions: {exc}[/danger]")

        elif sub == "use" and len(args) >= 2:
            sid = args[1]
            self.state.current_session = sid
            save_state(self.state)
            self.console.print(f"  [ok]switched to session: {sid}[/ok]")

        elif sub == "show":
            if not self.session_id:
                self.console.print("  [muted]no active session[/muted]")
                return
            try:
                from ..core.storage import WorkspaceStorage
                storage = WorkspaceStorage(ws.db_path)
                session = storage.legacy.load_session(self.session_id)
                if session:
                    self.console.print(f"  [accent]id:[/accent]       {session.id}")
                    self.console.print(f"  [accent]target:[/accent]   {session.target.canonical}")
                    self.console.print(f"  [accent]profile:[/accent]  {session.profile}")
                    self.console.print(f"  [accent]status:[/accent]   {session.status.value}")
                    self.console.print(f"  [accent]started:[/accent]  {session.started_at}")
                    self.console.print(f"  [accent]tools:[/accent]    {', '.join(session.tools_ran)}")
                else:
                    self.console.print(f"  [danger]session not found: {self.session_id}[/danger]")
            except Exception as exc:
                self.console.print(f"  [danger]failed to load session: {exc}[/danger]")

        else:
            self.console.print("[muted]usage: session list|use <id>|show[/muted]")

    # --- dispatch to drake CLI ---

    def _dispatch_drake(self, parts: list[str]) -> None:
        """Dispatch to existing Drake-X CLI commands with implicit context."""
        from .v2 import app as drake_app
        from typer.testing import CliRunner

        argv = list(parts)

        # Inject workspace context if not explicitly provided
        ws_flags = {"-w", "--workspace"}
        has_ws = any(a in ws_flags for a in argv)
        if not has_ws and self.workspace_name:
            # Insert -w after the subcommand group for commands that accept it
            ws_commands = {"apk", "pe", "report", "findings", "ai", "ioc", "recon", "web", "scope", "status"}
            if argv and argv[0].lower() in ws_commands:
                argv.extend(["-w", self.workspace_name])

        runner = CliRunner(mix_stderr=False)
        try:
            result = runner.invoke(drake_app, argv, catch_exceptions=False)
            if result.output:
                # Strip banner lines from output (they start with ANSI or spaces before the skull)
                lines = result.output.split("\n")
                for line in lines:
                    self.console.print(line, highlight=False)
        except SystemExit:
            pass
        except Exception as exc:
            self.console.print(f"[danger]command error: {exc}[/danger]")

        # Update state from last analysis if applicable
        if parts and parts[0].lower() in ("apk", "pe") and len(parts) >= 3:
            sample_path = parts[2] if len(parts) > 2 else ""
            if sample_path and Path(sample_path).exists():
                self.state.last_sample_path = str(Path(sample_path).resolve())
                save_state(self.state)

    # --- command table ---

    _COMMANDS: dict[str, any] = {
        "exit": _cmd_exit,
        "quit": _cmd_exit,
        "help": _cmd_help,
        "?": _cmd_help,
        "status": _cmd_status,
        "tools": _cmd_tools,
        "workspace": _cmd_workspace,
        "session": _cmd_session,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def console(ctx: typer.Context) -> None:
    """Launch the persistent investigation console.

    Maintains workspace and session context across commands. Renders
    the banner once. Dispatches to existing Drake-X commands with
    implicit context injection.
    """
    if ctx.invoked_subcommand is not None:
        return

    repl = InvestigationConsole()
    repl.run()

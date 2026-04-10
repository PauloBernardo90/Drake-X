"""``drake tools`` — list known integrations and their installation status."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

import typer

from ..cli_theme import build_tools_table, format_tool_installed, make_console
from ..constants import AUTHORIZED_USE_NOTICE
from ..core.plugin_loader import PluginLoader
from ..integrations.apk.ghidra import is_available as ghidra_available
from ..integrations.reporting.pandoc import is_available as pandoc_available
from . import _shared

app = typer.Typer(no_args_is_help=False, invoke_without_command=True, help="List supported integrations.")


@dataclass(frozen=True)
class SupportToolRow:
    name: str
    installed: bool
    profiles: tuple[str, ...]
    targets: tuple[str, ...]
    description: str


def _binary_available(*candidates: str) -> bool:
    return any(shutil.which(candidate) for candidate in candidates)


def _supporting_tool_rows() -> list[SupportToolRow]:
    """Supplementary toolchains used by APK, dynamic, intel, and reporting flows.

    These tools are not part of the recon plugin loader, but they are real
    operator-facing dependencies used by Drake-X workflows and should appear in
    ``drake tools`` so the environment picture is complete.
    """
    return [
        SupportToolRow(
            "aapt/aapt2",
            _binary_available("aapt2", "aapt"),
            ("apk-static",),
            ("apk",),
            "Android manifest and package metadata extraction.",
        ),
        SupportToolRow(
            "apktool",
            _binary_available("apktool"),
            ("apk-static",),
            ("apk",),
            "Resource decoding and smali extraction for APK static analysis.",
        ),
        SupportToolRow(
            "jadx",
            _binary_available("jadx"),
            ("apk-static",),
            ("apk",),
            "DEX decompilation to Java-like output for analyst review.",
        ),
        SupportToolRow(
            "unzip",
            _binary_available("unzip"),
            ("apk-static",),
            ("apk",),
            "Archive extraction and file inventory for APK contents.",
        ),
        SupportToolRow(
            "strings",
            _binary_available("strings"),
            ("apk-static",),
            ("apk", "native-lib"),
            "String extraction from APKs and embedded binaries.",
        ),
        SupportToolRow(
            "rabin2",
            _binary_available("rabin2"),
            ("apk-static", "native-static"),
            ("apk", "native-lib"),
            "radare2 metadata extraction for native binaries and APK payloads.",
        ),
        SupportToolRow(
            "yara",
            _binary_available("yara"),
            ("apk-static", "ioc-hunting"),
            ("apk", "artifact"),
            "Rule-based scanning of APKs and extracted artifacts.",
        ),
        SupportToolRow(
            "ghidra",
            ghidra_available(),
            ("native-static",),
            ("native-lib",),
            "Headless deeper native analysis and structured export support.",
        ),
        SupportToolRow(
            "frida",
            _binary_available("frida"),
            ("apk-dynamic",),
            ("android-device", "android-emulator"),
            "Dynamic observation and runtime validation on Android targets.",
        ),
        SupportToolRow(
            "adb",
            _binary_available("adb"),
            ("apk-dynamic",),
            ("android-device", "android-emulator"),
            "Android bridge for deployment, logs, and runtime interaction.",
        ),
        SupportToolRow(
            "pandoc",
            pandoc_available(),
            ("reporting",),
            ("markdown", "pdf"),
            "Markdown-to-PDF conversion for report export.",
        ),
    ]


@app.callback(invoke_without_command=True)
def list_tools(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path (optional)."),
) -> None:
    console = make_console()

    timeout = 180
    try:
        ws = _shared.resolve_workspace(workspace) if workspace else None
        if ws is not None:
            timeout = ws.config.default_timeout
    except SystemExit:
        pass

    loader = PluginLoader(default_timeout=timeout).load()

    table = build_tools_table()
    for entry in loader.all():
        table.add_row(
            entry.name,
            format_tool_installed(entry.installed),
            ", ".join(entry.profiles),
            ", ".join(entry.target_types),
            entry.description,
        )
    for entry in _supporting_tool_rows():
        table.add_row(
            entry.name,
            format_tool_installed(entry.installed),
            ", ".join(entry.profiles),
            ", ".join(entry.targets),
            entry.description,
        )
    console.print()
    console.print(table)
    console.print()
    console.print(f"[notice]{AUTHORIZED_USE_NOTICE}[/notice]")

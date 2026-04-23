"""Smali bytecode analyzer — extract classes, methods, and call edges from smali.

Parses the directory tree produced by ``apktool d`` to extract:

- Class declarations and their hierarchy
- Method declarations with access flags
- Invoke instructions (call graph edges)
- Android component registrations
"""

from __future__ import annotations

import re
from pathlib import Path

from ..logging import get_logger
from ..models.dex import CallEdge, DexClassInfo, DexMethodInfo

log = get_logger("dex.smali_analyzer")

# Regex patterns for smali parsing
_CLASS_RE = re.compile(r"^\.class\s+(.*?)\s+(L[\w/$]+;)", re.MULTILINE)
_SUPER_RE = re.compile(r"^\.super\s+(L[\w/$]+;)", re.MULTILINE)
_IMPLEMENTS_RE = re.compile(r"^\.implements\s+(L[\w/$]+;)", re.MULTILINE)
_SOURCE_RE = re.compile(r"^\.source\s+\"(.+?)\"", re.MULTILINE)
_METHOD_RE = re.compile(
    r"^\.method\s+(.*?)\s*([\w<>$]+)\((.*?)\)(.*?)$", re.MULTILINE
)
_INVOKE_RE = re.compile(
    r"^\s+invoke-\w+\s+\{[^}]*\},\s+(L[\w/$]+;)->([\w<>$]+)\(", re.MULTILINE
)
_FIELD_RE = re.compile(r"^\.field\s+", re.MULTILINE)


def parse_smali_directory(
    smali_dir: Path,
    *,
    source_dex: str = "",
    max_files: int = 50_000,
) -> tuple[list[DexClassInfo], list[DexMethodInfo], list[CallEdge]]:
    """Walk a smali directory tree and extract structural information.

    Parameters
    ----------
    smali_dir:
        Root of the smali directory (e.g., ``work_dir/smali``).
    source_dex:
        Label for the originating DEX file.
    max_files:
        Safety cap on files processed.

    Returns
    -------
    tuple of (classes, methods, call_edges)
    """
    classes: list[DexClassInfo] = []
    methods: list[DexMethodInfo] = []
    call_edges: list[CallEdge] = []

    smali_dir = Path(smali_dir)
    if not smali_dir.is_dir():
        log.warning("Smali directory not found: %s", smali_dir)
        return classes, methods, call_edges

    smali_files = list(smali_dir.rglob("*.smali"))
    if len(smali_files) > max_files:
        log.warning(
            "Too many smali files (%d), capping at %d",
            len(smali_files), max_files,
        )
        smali_files = smali_files[:max_files]

    for smali_path in smali_files:
        try:
            text = smali_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        cls, meths, edges = _parse_single_smali(text, source_dex=source_dex)
        if cls:
            classes.append(cls)
        methods.extend(meths)
        call_edges.extend(edges)

    log.info(
        "Parsed %d smali files → %d classes, %d methods, %d call edges",
        len(smali_files), len(classes), len(methods), len(call_edges),
    )
    return classes, methods, call_edges


def _parse_single_smali(
    text: str, *, source_dex: str = ""
) -> tuple[DexClassInfo | None, list[DexMethodInfo], list[CallEdge]]:
    """Parse a single .smali file."""
    methods: list[DexMethodInfo] = []
    call_edges: list[CallEdge] = []

    # Class declaration
    class_match = _CLASS_RE.search(text)
    if not class_match:
        return None, methods, call_edges

    access_flags = class_match.group(1).strip()
    class_descriptor = class_match.group(2)
    class_name = _descriptor_to_name(class_descriptor)

    # Superclass
    super_match = _SUPER_RE.search(text)
    superclass = _descriptor_to_name(super_match.group(1)) if super_match else ""

    # Interfaces
    interfaces = [
        _descriptor_to_name(m.group(1)) for m in _IMPLEMENTS_RE.finditer(text)
    ]

    # Fields (count only)
    field_count = len(_FIELD_RE.findall(text))

    # Methods
    current_method: str | None = None
    for m in _METHOD_RE.finditer(text):
        mflags = m.group(1).strip()
        mname = m.group(2)
        methods.append(DexMethodInfo(
            class_name=class_name,
            method_name=mname,
            source_dex=source_dex,
            access_flags=mflags,
            descriptor=f"({m.group(3)}){m.group(4)}",
            is_native="native" in mflags,
            is_constructor=mname in ("<init>", "<clinit>"),
        ))
        current_method = mname

    # Call edges (invoke-*)
    for inv in _INVOKE_RE.finditer(text):
        callee_class = _descriptor_to_name(inv.group(1))
        callee_method = inv.group(2)
        # Determine which method this invoke belongs to by position
        caller_method = _find_enclosing_method(text, inv.start())
        call_edges.append(CallEdge(
            caller_class=class_name,
            caller_method=caller_method or "<unknown>",
            callee_class=callee_class,
            callee_method=callee_method,
            source_dex=source_dex,
            edge_type="invoke",
        ))

    is_abstract = "abstract" in access_flags
    is_interface = "interface" in access_flags
    package = _extract_package(class_name)

    cls = DexClassInfo(
        class_name=class_name,
        source_dex=source_dex,
        access_flags=access_flags,
        superclass=superclass,
        interfaces=interfaces,
        method_count=len(methods),
        field_count=field_count,
        is_abstract=is_abstract,
        is_interface=is_interface,
        package=package,
    )

    return cls, methods, call_edges


def _find_enclosing_method(text: str, pos: int) -> str | None:
    """Find the method name that contains the given position."""
    last_method = None
    for m in _METHOD_RE.finditer(text):
        if m.start() > pos:
            break
        last_method = m.group(2)
    return last_method


def _descriptor_to_name(descriptor: str) -> str:
    """Convert ``Lcom/foo/Bar;`` to ``com.foo.Bar``."""
    return descriptor.lstrip("L").rstrip(";").replace("/", ".")


def _extract_package(class_name: str) -> str:
    parts = class_name.rsplit(".", 1)
    return parts[0] if len(parts) > 1 else ""


def collect_smali_directories(apktool_dir: Path) -> list[tuple[Path, str]]:
    """Find all smali directories in an apktool output.

    Returns list of (directory_path, inferred_dex_name) tuples.
    apktool produces ``smali/`` for classes.dex, ``smali_classes2/`` for
    classes2.dex, etc.
    """
    results: list[tuple[Path, str]] = []
    apktool_dir = Path(apktool_dir)

    # Primary: smali/
    primary = apktool_dir / "smali"
    if primary.is_dir():
        results.append((primary, "classes.dex"))

    # Secondary: smali_classes2/, smali_classes3/, ...
    for d in sorted(apktool_dir.iterdir()):
        if d.is_dir() and d.name.startswith("smali_classes"):
            suffix = d.name.replace("smali_", "")
            dex_name = f"{suffix}.dex"
            results.append((d, dex_name))

    return results

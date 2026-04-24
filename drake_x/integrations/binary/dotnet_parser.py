"""CLR metadata parser for .NET PE binaries.

Drake-X's native PE parser (:mod:`drake_x.integrations.binary.pe_parser`)
treats every PE binary as native, and as a result produces very small
evidence graphs for .NET samples (all behavior lives in CLR metadata,
not in the classic PE import table). This module fills the gap:

- :func:`is_dotnet` detects a .NET binary via the COM descriptor
  directory (``DATA_DIRECTORY[14]``).
- :func:`parse_dotnet` extracts the CLR metadata tables (AssemblyRef,
  TypeRef, MemberRef, ImplMap) and the user-strings heap using the
  ``dnfile`` library.
- :func:`synthesize_native_imports` converts P/Invokes and
  member-references into synthetic :class:`PeImport` records so that
  the downstream import-risk classifier, evidence-graph writer, and
  rule-based baseline operate on .NET samples uniformly, with no
  further code changes outside this module.

The module degrades gracefully if ``dnfile`` is unavailable or the
binary is malformed; in that case :func:`parse_dotnet` returns an
empty :class:`ManagedMetadata` with a non-empty ``warnings`` list.

References: ECMA-335 partitions II (Metadata) and III (CIL).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...logging import get_logger
from ...models.pe import ManagedMetadata, PeImport

log = get_logger("dotnet_parser")


# Index of the COM descriptor directory in the PE optional header's
# DATA_DIRECTORY table. ECMA-335 §II.25.3.3.
COM_DESCRIPTOR_DIRECTORY_INDEX = 14


def is_available() -> bool:
    """Return True if the ``dnfile`` library is installed."""
    try:
        import dnfile  # noqa: F401
        return True
    except ImportError:
        return False


def is_dotnet(pe: Any) -> bool:
    """Return True if *pe* is a .NET (CLR) binary.

    Detection is based on the presence of a non-empty
    ``IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`` entry in the optional
    header (index 14). This is the canonical runtime-loader marker and
    is more reliable than checking for ``mscoree.dll`` in the import
    table (which mixed-mode assemblies may lack).
    """
    try:
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[COM_DESCRIPTOR_DIRECTORY_INDEX]
        return bool(dd.VirtualAddress and dd.Size)
    except (AttributeError, IndexError):
        return False


def parse_dotnet(path: Path) -> ManagedMetadata:
    """Parse the CLR metadata of a .NET PE binary.

    Returns a populated :class:`ManagedMetadata`; warnings are recorded
    on the returned object rather than raised, mirroring the behavior
    of :func:`pe_parser.parse_pe`.
    """
    out = ManagedMetadata()

    if not is_available():
        out.warnings.append("dnfile not installed (pip install dnfile)")
        return out

    import dnfile  # imported lazily so non-.NET flows pay no cost

    try:
        dn = dnfile.dnPE(str(path), fast_load=False)
    except Exception as exc:  # noqa: BLE001
        out.warnings.append(f"dnfile load failed: {exc}")
        return out

    try:
        _fill_cor20_header(dn, out)
        _fill_assembly_refs(dn, out)
        _fill_type_refs(dn, out)
        _fill_member_refs(dn, out)
        _fill_pinvokes(dn, out)
        _fill_user_strings(dn, out)
        _fill_fingerprints(out)
    except Exception as exc:  # noqa: BLE001
        # Partial parse: keep whatever has been filled so far, record why
        # the rest failed. This mirrors the native parser's behavior.
        out.warnings.append(f"partial .NET parse: {exc}")
        log.debug("dotnet parse partial failure: %s", exc, exc_info=True)

    return out


# ---------------------------------------------------------------------------
# Internal fillers (one per metadata area)
# ---------------------------------------------------------------------------


def _fill_cor20_header(dn: Any, out: ManagedMetadata) -> None:
    try:
        s = dn.net.struct
        out.runtime_version = f"{s.MajorRuntimeVersion}.{s.MinorRuntimeVersion}"
        flags = int(s.Flags)
        out.il_only = bool(flags & 0x1)
        out.has_strong_name = bool(flags & 0x8)
        out.requires_32bit = bool(flags & 0x2)
        out.entry_point_token = hex(int(s.EntryPointTokenOrRVA))
    except AttributeError as exc:
        out.warnings.append(f"COR20 header incomplete: {exc}")


def _safe_value(field: Any) -> str:
    """Extract the printable value of a dnfile metadata row field."""
    if field is None:
        return ""
    v = getattr(field, "value", field)
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v) if v is not None else ""


def _fill_assembly_refs(dn: Any, out: ManagedMetadata) -> None:
    tbl = getattr(dn.net.mdtables, "AssemblyRef", None)
    if not tbl:
        return
    for row in tbl.rows:
        name = _safe_value(getattr(row, "Name", None))
        culture = _safe_value(getattr(row, "Culture", None))
        version = ""
        try:
            version = (f"{row.MajorVersion}.{row.MinorVersion}."
                       f"{row.BuildNumber}.{row.RevisionNumber}")
        except AttributeError:
            pass
        if name:
            out.assembly_refs.append({
                "name": name, "version": version, "culture": culture,
            })


def _fill_type_refs(dn: Any, out: ManagedMetadata) -> None:
    tbl = getattr(dn.net.mdtables, "TypeRef", None)
    if not tbl:
        return
    for row in tbl.rows:
        name = _safe_value(getattr(row, "TypeName", None))
        ns = _safe_value(getattr(row, "TypeNamespace", None))
        if not name:
            continue
        out.type_refs.append(f"{ns}.{name}" if ns else name)


def _fill_member_refs(dn: Any, out: ManagedMetadata) -> None:
    """Emit every MemberRef as a ``Namespace.Type.Member`` string.

    Dnfile resolves the Class coded-index to the containing TypeRef
    automatically via the ``Class`` attribute's ``row`` back-reference.
    """
    tbl = getattr(dn.net.mdtables, "MemberRef", None)
    if not tbl:
        return
    for row in tbl.rows:
        name = _safe_value(getattr(row, "Name", None))
        if not name:
            continue
        class_label = ""
        try:
            parent_row = row.Class.row
            if parent_row is not None:
                type_name = _safe_value(getattr(parent_row, "TypeName", None))
                type_ns = _safe_value(getattr(parent_row, "TypeNamespace", None))
                class_label = (f"{type_ns}.{type_name}" if type_ns else type_name)
        except AttributeError:
            pass
        qualified = f"{class_label}.{name}" if class_label else name
        out.member_refs.append(qualified)


def _fill_pinvokes(dn: Any, out: ManagedMetadata) -> None:
    """Extract ImplMap rows as native-API invocations.

    ImplMap entries are the P/Invoke declarations — the literal native
    Win32 APIs that the .NET sample calls through marshalling. These
    are the same semantic units as native imports and must appear in
    the evidence graph alongside them so that rule-based correlators
    (``rules_baseline.yaml``) fire uniformly.
    """
    tbl = getattr(dn.net.mdtables, "ImplMap", None)
    if not tbl:
        return
    for row in tbl.rows:
        fn = _safe_value(getattr(row, "ImportName", None))
        dll = ""
        try:
            mod_row = row.ImportScope.row
            if mod_row is not None:
                dll = _safe_value(getattr(mod_row, "Name", None))
        except AttributeError:
            pass
        if fn:
            out.pinvokes.append({"dll": dll, "function": fn})


def _fill_user_strings(dn: Any, out: ManagedMetadata) -> None:
    """Extract the #US (user-strings) heap.

    We bound the result to 512 entries to keep downstream prompts
    tractable. dnfile exposes the heap via ``dn.net.user_strings``.
    """
    us = getattr(dn.net, "user_strings", None)
    if us is None:
        return
    try:
        entries = us.get_all() if hasattr(us, "get_all") else list(us)
    except Exception as exc:  # noqa: BLE001
        out.warnings.append(f"user-strings extraction failed: {exc}")
        return
    bounded: list[str] = []
    for e in entries[:512]:
        v = getattr(e, "value", e)
        if isinstance(v, bytes):
            v = v.decode("utf-8", errors="replace")
        v = str(v or "").strip()
        if v and len(v) >= 3:
            bounded.append(v)
    out.user_strings = bounded


# ---------------------------------------------------------------------------
# Obfuscator fingerprints (P1)
# ---------------------------------------------------------------------------

_OBFUSCATOR_SIGNATURES: list[tuple[str, callable]] = [
    ("ConfuserEx",
     lambda out: any(r["name"].lower().startswith(("confuser", "koi"))
                     for r in out.assembly_refs)
                 or any("confused" in t.lower() for t in out.type_refs)),
    ("SmartAssembly",
     lambda out: any("smartassembly" in r["name"].lower() for r in out.assembly_refs)
                 or any("smartassembly" in t.lower() for t in out.type_refs)),
    (".NET Reactor",
     lambda out: any(t.startswith("__") for t in out.type_refs)),
    ("Eazfuscator.NET",
     lambda out: any("eazfuscator" in t.lower() for t in out.type_refs)),
    ("Babel.NET",
     lambda out: any("babel" in r["name"].lower() for r in out.assembly_refs)),
]


def _fill_fingerprints(out: ManagedMetadata) -> None:
    for name, test in _OBFUSCATOR_SIGNATURES:
        try:
            if test(out):
                out.obfuscator_fingerprints.append(name)
        except Exception:  # noqa: BLE001
            continue


# ---------------------------------------------------------------------------
# Bridge: synthesize PeImport records from .NET metadata.
# ---------------------------------------------------------------------------


def synthesize_native_imports(managed: ManagedMetadata) -> list[PeImport]:
    """Lift managed artefacts into :class:`PeImport` records.

    The downstream graph writer, risk classifier, and rule-based
    baseline are all written against :class:`PeImport`. Rather than
    duplicate them for .NET, we project the relevant managed artefacts
    onto the same shape:

    - Every **P/Invoke** becomes a :class:`PeImport` with
      ``dll=<native-dll>`` and ``function=<native-function>``. The
      Win32 rules (``CreateRemoteThread``, ``SetWindowsHookExA``, ...)
      fire on these without modification.
    - Every **MemberRef** becomes a :class:`PeImport` with
      ``dll=<AssemblyRef-name>`` and ``function=<Type.Member>``. New
      .NET-aware rules in ``rules_baseline.yaml`` match against these
      qualified names (e.g. ``System.Net.Mail.SmtpClient.Send``).

    Ordinals are never set for synthesized records.
    """
    synth: list[PeImport] = []
    for p in managed.pinvokes:
        dll = (p.get("dll") or "").strip()
        fn = (p.get("function") or "").strip()
        if fn:
            synth.append(PeImport(
                dll=dll or "(pinvoke)",
                function=fn,
                notes="pinvoke",
            ))
    for qualified in managed.member_refs:
        synth.append(PeImport(
            dll="(managed)",
            function=qualified,
            notes="member_ref",
        ))
    return synth

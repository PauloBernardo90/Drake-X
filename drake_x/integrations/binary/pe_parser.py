"""PE file parser using ``pefile`` library.

Extracts structured metadata from Windows PE binaries: headers,
sections, imports, exports, resources, anomalies, and protection
status. Degrades gracefully if ``pefile`` is not installed.

This is the primary PE parser. No fallback parser is used in v0.8.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any

from ...logging import get_logger
from ...models.pe import (
    PeAnomaly,
    PeExport,
    PeHeader,
    PeImport,
    PeMachine,
    PeMetadata,
    PeProtectionStatus,
    PeResource,
    PeSection,
)

log = get_logger("pe_parser")


def is_available() -> bool:
    """Check if the pefile library is installed."""
    try:
        import pefile  # noqa: F401
        return True
    except ImportError:
        return False


def parse_pe(path: Path) -> dict[str, Any]:
    """Parse a PE file and return structured components.

    Returns a dict with keys: header, sections, imports, exports,
    resources, anomalies, protection, warnings.

    If ``pefile`` is not installed, returns a dict with an error warning
    and empty structures.
    """
    result: dict[str, Any] = {
        "header": PeHeader(),
        "sections": [],
        "imports": [],
        "exports": [],
        "resources": [],
        "anomalies": [],
        "protection": PeProtectionStatus(),
        "warnings": [],
    }

    if not is_available():
        result["warnings"].append("pefile library not installed. Install with: pip install pefile")
        return result

    import pefile

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        result["warnings"].append(f"PE format error: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001
        result["warnings"].append(f"PE parsing failed: {exc}")
        return result

    try:
        result["header"] = _parse_header(pe)
        result["sections"] = _parse_sections(pe)
        result["imports"] = _parse_imports(pe)
        result["exports"] = _parse_exports(pe)
        result["resources"] = _parse_resources(pe)
        result["protection"] = _parse_protection(pe)
        result["anomalies"] = _detect_anomalies(pe, result["sections"], result["header"])
    except Exception as exc:  # noqa: BLE001
        log.warning("PE parsing partially failed: %s", exc)
        result["warnings"].append(f"Partial parsing failure: {exc}")
    finally:
        pe.close()

    return result


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------

_MACHINE_MAP = {
    0x14C: PeMachine.I386,
    0x8664: PeMachine.AMD64,
    0x1C0: PeMachine.ARM,
    0xAA64: PeMachine.ARM64,
}

_SUBSYSTEM_MAP = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    7: "posix_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
}


def _parse_header(pe: Any) -> PeHeader:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    machine = _MACHINE_MAP.get(fh.Machine, PeMachine.UNKNOWN)

    dll_chars = []
    if hasattr(oh, "DllCharacteristics"):
        dc = oh.DllCharacteristics
        if dc & 0x0020:
            dll_chars.append("HIGH_ENTROPY_VA")
        if dc & 0x0040:
            dll_chars.append("DYNAMIC_BASE")
        if dc & 0x0100:
            dll_chars.append("NX_COMPAT")
        if dc & 0x0200:
            dll_chars.append("NO_ISOLATION")
        if dc & 0x0400:
            dll_chars.append("NO_SEH")
        if dc & 0x0800:
            dll_chars.append("NO_BIND")
        if dc & 0x1000:
            dll_chars.append("APPCONTAINER")
        if dc & 0x2000:
            dll_chars.append("WDM_DRIVER")
        if dc & 0x4000:
            dll_chars.append("GUARD_CF")
        if dc & 0x8000:
            dll_chars.append("TERMINAL_SERVER_AWARE")
        if dc & 0x0080:
            dll_chars.append("FORCE_INTEGRITY")

    import time
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(fh.TimeDateStamp))
    except (ValueError, OSError):
        ts = str(fh.TimeDateStamp)

    is_dll = bool(fh.Characteristics & 0x2000)
    is_exe = not is_dll

    return PeHeader(
        machine=machine,
        image_base=hex(oh.ImageBase),
        entry_point=hex(oh.AddressOfEntryPoint),
        number_of_sections=fh.NumberOfSections,
        timestamp=ts,
        subsystem=_SUBSYSTEM_MAP.get(oh.Subsystem, str(oh.Subsystem)),
        dll_characteristics=dll_chars,
        size_of_image=oh.SizeOfImage,
        size_of_headers=oh.SizeOfHeaders,
        checksum=hex(oh.CheckSum),
        linker_version=f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        is_dll=is_dll,
        is_exe=is_exe,
    )


def _parse_sections(pe: Any) -> list[PeSection]:
    sections = []
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        entropy = sec.get_entropy()
        chars = []
        c = sec.Characteristics
        is_exec = bool(c & 0x20000000)
        is_write = bool(c & 0x80000000)
        if c & 0x00000020:
            chars.append("CODE")
        if c & 0x00000040:
            chars.append("INITIALIZED_DATA")
        if c & 0x00000080:
            chars.append("UNINITIALIZED_DATA")
        if is_exec:
            chars.append("EXECUTE")
        if c & 0x40000000:
            chars.append("READ")
        if is_write:
            chars.append("WRITE")

        sections.append(PeSection(
            name=name,
            virtual_address=hex(sec.VirtualAddress),
            virtual_size=sec.Misc_VirtualSize,
            raw_size=sec.SizeOfRawData,
            entropy=round(entropy, 4),
            characteristics=chars,
            is_executable=is_exec,
            is_writable=is_write,
        ))
    return sections


def _parse_imports(pe: Any) -> list[PeImport]:
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
        for imp in entry.imports:
            func = imp.name.decode("utf-8", errors="replace") if imp.name else ""
            imports.append(PeImport(
                dll=dll,
                function=func,
                ordinal=imp.ordinal if not imp.name else None,
            ))
    return imports


def _parse_exports(pe: Any) -> list[PeExport]:
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode("utf-8", errors="replace") if exp.name else ""
        exports.append(PeExport(
            name=name,
            ordinal=exp.ordinal,
            address=hex(exp.address),
        ))
    return exports


def _parse_resources(pe: Any) -> list[PeResource]:
    resources = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return resources

    _RESOURCE_TYPES = {
        1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
        6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
        10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
        14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
    }

    try:
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = _RESOURCE_TYPES.get(
                res_type.id, res_type.name.decode("utf-8", errors="replace") if res_type.name else str(res_type.id)
            )
            if not hasattr(res_type, "directory"):
                continue
            for res_id in res_type.directory.entries:
                if not hasattr(res_id, "directory"):
                    continue
                for res_lang in res_id.directory.entries:
                    data_entry = res_lang.data
                    size = data_entry.struct.Size
                    # Compute entropy of resource data
                    try:
                        data = pe.get_data(data_entry.struct.OffsetToData, size)
                        entropy = _compute_entropy(data) if data else 0.0
                    except Exception:
                        entropy = 0.0
                    resources.append(PeResource(
                        name=str(res_id.id or (res_id.name.decode("utf-8", errors="replace") if res_id.name else "")),
                        resource_type=str(type_name),
                        language=str(res_lang.id),
                        size=size,
                        entropy=round(entropy, 4),
                    ))
    except Exception as exc:  # noqa: BLE001
        log.debug("Resource parsing partially failed: %s", exc)

    return resources[:100]  # Bound output


def _parse_protection(pe: Any) -> PeProtectionStatus:
    dc = pe.OPTIONAL_HEADER.DllCharacteristics if hasattr(pe, "OPTIONAL_HEADER") else 0
    notes = []

    aslr = bool(dc & 0x0040)
    dep = bool(dc & 0x0100)
    cfg = bool(dc & 0x4000)
    no_seh = bool(dc & 0x0400)
    high_entropy = bool(dc & 0x0020)
    force_integrity = bool(dc & 0x0080)
    no_isolation = bool(dc & 0x0200)

    # SafeSEH is indicated by the presence of the load config directory
    safe_seh = False
    if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG
        if hasattr(lc, "struct") and hasattr(lc.struct, "SEHandlerCount"):
            safe_seh = lc.struct.SEHandlerCount > 0

    # Stack cookies (GS) — heuristic: look for __security_cookie import
    stack_cookies = False
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and b"__security_check_cookie" in imp.name:
                    stack_cookies = True
                    break

    if not aslr:
        notes.append("ASLR is disabled — binary loads at fixed address")
    if not dep:
        notes.append("DEP/NX is disabled — stack/heap may be executable")
    if no_seh:
        notes.append("NO_SEH flag set — SEH exploitation mitigation absent")
    if not cfg:
        notes.append("Control Flow Guard is disabled")

    return PeProtectionStatus(
        dep_enabled=dep,
        aslr_enabled=aslr,
        cfg_enabled=cfg,
        safe_seh=safe_seh,
        stack_cookies=stack_cookies,
        high_entropy_va=high_entropy,
        force_integrity=force_integrity,
        no_isolation=no_isolation,
        notes=notes,
    )


def _detect_anomalies(pe: Any, sections: list[PeSection], header: PeHeader) -> list[PeAnomaly]:
    anomalies = []

    # Timestamp anomalies
    ts = pe.FILE_HEADER.TimeDateStamp
    if ts == 0:
        anomalies.append(PeAnomaly(
            anomaly_type="zero_timestamp",
            description="PE timestamp is zero — likely stripped or forged",
            severity="medium",
            evidence=f"TimeDateStamp = 0",
        ))
    elif ts > 2000000000:
        anomalies.append(PeAnomaly(
            anomaly_type="future_timestamp",
            description="PE timestamp is in the far future — likely forged",
            severity="medium",
            evidence=f"TimeDateStamp = {ts}",
        ))

    # Section anomalies
    standard_names = {".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".edata", ".idata", ".tls", ".pdata"}
    for sec in sections:
        # Unusual section names
        if sec.name and sec.name not in standard_names and not sec.name.startswith("."):
            anomalies.append(PeAnomaly(
                anomaly_type="unusual_section_name",
                description=f"Non-standard section name: {sec.name}",
                severity="low",
                evidence=f"Section '{sec.name}' is not a standard PE section name",
            ))

        # High entropy (likely packed/encrypted)
        if sec.entropy > 7.0:
            anomalies.append(PeAnomaly(
                anomaly_type="high_entropy_section",
                description=f"Section {sec.name} has high entropy ({sec.entropy:.2f}) — possibly packed or encrypted",
                severity="medium",
                evidence=f"Section '{sec.name}' entropy = {sec.entropy:.4f}",
            ))

        # Writable + executable
        if sec.is_writable and sec.is_executable:
            anomalies.append(PeAnomaly(
                anomaly_type="writable_executable_section",
                description=f"Section {sec.name} is both writable and executable — suspicious",
                severity="high",
                evidence=f"Section '{sec.name}' has WRITE + EXECUTE characteristics",
            ))

        # Raw size much smaller than virtual size (possible unpacking stub)
        if sec.virtual_size > 0 and sec.raw_size > 0:
            ratio = sec.virtual_size / sec.raw_size
            if ratio > 10:
                anomalies.append(PeAnomaly(
                    anomaly_type="inflated_virtual_size",
                    description=f"Section {sec.name} virtual size is {ratio:.0f}x raw size — possible unpacking",
                    severity="medium",
                    evidence=f"VirtualSize={sec.virtual_size}, RawSize={sec.raw_size}",
                ))

    # Entry point outside .text
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    text_sections = [s for s in pe.sections if b".text" in s.Name]
    if text_sections:
        ts_sec = text_sections[0]
        ep_in_text = ts_sec.VirtualAddress <= ep < (ts_sec.VirtualAddress + ts_sec.Misc_VirtualSize)
        if not ep_in_text:
            ep_sec = None
            for s in pe.sections:
                if s.VirtualAddress <= ep < (s.VirtualAddress + s.Misc_VirtualSize):
                    ep_sec = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                    break
            anomalies.append(PeAnomaly(
                anomaly_type="entry_point_outside_text",
                description=f"Entry point ({hex(ep)}) is outside .text section" +
                            (f" — located in {ep_sec}" if ep_sec else ""),
                severity="medium",
                evidence=f"EP={hex(ep)}, .text VA range={hex(ts_sec.VirtualAddress)}-{hex(ts_sec.VirtualAddress + ts_sec.Misc_VirtualSize)}",
            ))

    # Very few imports (possible packing)
    import_count = len([i for i in (pe.DIRECTORY_ENTRY_IMPORT if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else [])])
    if 0 < import_count <= 2:
        anomalies.append(PeAnomaly(
            anomaly_type="minimal_imports",
            description=f"Only {import_count} imported DLL(s) — may indicate packing or manual import resolution",
            severity="medium",
            evidence=f"DIRECTORY_ENTRY_IMPORT has {import_count} entries",
        ))

    return anomalies


def _compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

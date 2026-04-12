"""Bounded disassembly via Capstone.

Provides entry-point-region disassembly for PE binaries. The v0.8
implementation disassembles a bounded region starting at the PE entry
point (up to 200 instructions / 4 KB of code). This is NOT
function-scoped analysis — it captures the initial execution path
without attempting function boundary detection.

Output is stored as a structured JSON artifact, NOT as canonical
evidence graph nodes (per v0.8 doctrine).

Degrades gracefully if Capstone is not installed.
"""

from __future__ import annotations

from typing import Any

from ...logging import get_logger

log = get_logger("capstone_engine")


def is_available() -> bool:
    """Check if the Capstone library is installed."""
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        return False


def disassemble_entry_region(
    code_bytes: bytes,
    base_address: int,
    *,
    arch: str = "x86",
    mode: str = "32",
    max_instructions: int = 200,
) -> list[dict[str, Any]]:
    """Disassemble a bounded region of code starting at base_address.

    Returns a list of instruction dicts with: address, mnemonic,
    op_str, size, bytes_hex. Limited to max_instructions to prevent
    unbounded output.

    This is a bounded artifact, not a graph-level entity.
    """
    if not is_available():
        return []

    import capstone

    arch_map = {
        ("x86", "32"): (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        ("x86", "64"): (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        ("amd64", "64"): (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        ("arm", "32"): (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        ("arm64", "64"): (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }

    cs_arch, cs_mode = arch_map.get((arch.lower(), mode), (capstone.CS_ARCH_X86, capstone.CS_MODE_32))

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False  # No detailed info needed for bounded output

    instructions = []
    for insn in md.disasm(code_bytes, base_address):
        instructions.append({
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "size": insn.size,
            "bytes_hex": insn.bytes.hex(),
        })
        if len(instructions) >= max_instructions:
            break

    return instructions


def disassemble_pe_entry(
    pe_path: str,
    *,
    max_instructions: int = 200,
) -> dict[str, Any]:
    """Disassemble the entry point region of a PE file.

    Returns a dict with: entry_point, arch, instructions, warnings.
    Uses pefile to locate the entry point and extract code bytes.
    """
    result: dict[str, Any] = {
        "entry_point": "",
        "arch": "",
        "instructions": [],
        "warnings": [],
    }

    if not is_available():
        result["warnings"].append("Capstone not installed")
        return result

    try:
        import pefile
    except ImportError:
        result["warnings"].append("pefile not installed — cannot locate entry point")
        return result

    try:
        pe = pefile.PE(pe_path, fast_load=True)
    except Exception as exc:  # noqa: BLE001
        result["warnings"].append(f"PE load failed: {exc}")
        return result

    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        machine = pe.FILE_HEADER.Machine

        if machine == 0x8664:
            arch, mode = "x86", "64"
        elif machine == 0x14C:
            arch, mode = "x86", "32"
        else:
            arch, mode = "x86", "32"

        result["entry_point"] = hex(ep)
        result["arch"] = f"{arch}_{mode}"

        # Find the section containing the entry point
        ep_offset = None
        for section in pe.sections:
            sec_start = section.VirtualAddress
            sec_end = sec_start + section.Misc_VirtualSize
            if sec_start <= ep < sec_end:
                ep_offset = section.PointerToRawData + (ep - sec_start)
                break

        if ep_offset is None:
            result["warnings"].append("Entry point not within any section")
            pe.close()
            return result

        # Read bounded code bytes (max 4KB from entry point)
        code_size = min(4096, pe.OPTIONAL_HEADER.SizeOfImage - ep)
        code_bytes = pe.get_data(ep, code_size)

        result["instructions"] = disassemble_entry_region(
            code_bytes,
            pe.OPTIONAL_HEADER.ImageBase + ep,
            arch=arch,
            mode=mode,
            max_instructions=max_instructions,
        )
    except Exception as exc:  # noqa: BLE001
        result["warnings"].append(f"Disassembly failed: {exc}")
    finally:
        pe.close()

    return result

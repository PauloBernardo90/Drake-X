"""Minimal stdlib-only ELF parser (v1.0).

Uses :mod:`pyelftools` when available (richer output) and falls back
to a bounded stdlib-only parser that reads just enough of the ELF
header to populate :class:`ElfHeader`. Graceful degradation is
documented via ``tools_skipped`` / ``warnings`` on the result.

This parser is deliberately shallow — v1.0 exposes ELF as a
first-class workflow but does NOT claim exploit-awareness parity
with PE. See the module-level docstring for scope.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def is_available() -> bool:
    """Structured ELF parsing via pyelftools is optional."""
    try:
        import elftools  # type: ignore  # noqa: F401
        return True
    except Exception:
        return False


def parse_elf_stdlib(path: Path) -> dict[str, Any]:
    """Bounded stdlib-only parse — header only.

    Reads only the ELF identification + file header. Enough to
    populate architecture, endianness, bitness, and file type.
    """
    with open(path, "rb") as fh:
        ident = fh.read(16)
        if len(ident) < 16 or ident[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        ei_class = ident[4]       # 1=32, 2=64
        ei_data = ident[5]        # 1=LE, 2=BE
        bits = 32 if ei_class == 1 else 64
        little = ei_data == 1
        endian = "<" if little else ">"

        # File-header layout differs by bitness; we only need e_type + e_machine.
        if bits == 32:
            hdr = fh.read(36)
            e_type, e_machine = struct.unpack(endian + "HH", hdr[:4])
            entry = struct.unpack(endian + "I", hdr[8:12])[0]
        else:
            hdr = fh.read(48)
            e_type, e_machine = struct.unpack(endian + "HH", hdr[:4])
            entry = struct.unpack(endian + "Q", hdr[8:16])[0]

    file_type_map = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
    arch_map = {
        0x03: "x86",
        0x3E: "x86_64",
        0x28: "arm",
        0xB7: "aarch64",
        0x08: "mips",
        0xF3: "riscv",
    }
    return {
        "bits": bits,
        "little_endian": little,
        "file_type": file_type_map.get(e_type, "UNKNOWN"),
        "arch": arch_map.get(e_machine, "unknown"),
        "entry_point": hex(entry),
    }


def parse_elf_full(path: Path) -> dict[str, Any]:
    """Rich parse using pyelftools. Returns an augmented dict."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection

    out: dict[str, Any] = parse_elf_stdlib(path)
    sections: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []

    # Protection profile
    nx = False
    pie = False
    relro = "none"
    canary = False
    fortify = False

    with open(path, "rb") as fh:
        elf = ELFFile(fh)

        for sec in elf.iter_sections():
            flags = []
            sh_flags = sec.header["sh_flags"]
            if sh_flags & 0x1:
                flags.append("WRITE")
            if sh_flags & 0x2:
                flags.append("ALLOC")
            if sh_flags & 0x4:
                flags.append("EXECINSTR")
            sections.append({
                "name": sec.name or "",
                "size": int(sec.header.get("sh_size", 0)),
                "flags": flags,
                "is_executable": "EXECINSTR" in flags,
                "is_writable": "WRITE" in flags,
            })

        # Dynamic section → DT_NEEDED libraries
        needed_libs = []
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed_libs.append(tag.needed)
                    elif tag.entry.d_tag == "DT_BIND_NOW":
                        if relro == "partial":
                            relro = "full"
                    elif tag.entry.d_tag == "DT_FLAGS_1":
                        # DF_1_NOW=1, DF_1_PIE=0x08000000
                        val = int(tag.entry.d_val)
                        if val & 0x08000000:
                            pie = True
                        if val & 0x1:
                            if relro == "partial":
                                relro = "full"

        # GNU_STACK segment controls NX
        for seg in elf.iter_segments():
            if seg.header["p_type"] == "PT_GNU_STACK":
                if not (seg.header["p_flags"] & 0x1):
                    nx = True
            if seg.header["p_type"] == "PT_GNU_RELRO":
                if relro == "none":
                    relro = "partial"

        # Imported symbols (.dynsym undefined)
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is not None:
            for sym in dynsym.iter_symbols():
                if sym.entry["st_shndx"] == "SHN_UNDEF" and sym.name:
                    imports.append({
                        "library": "",   # pyelftools does not carry per-symbol origin
                        "symbol": sym.name,
                        "binding": str(sym.entry["st_info"]["bind"]),
                        "type": str(sym.entry["st_info"]["type"]),
                    })
                    if sym.name in ("__stack_chk_fail", "__stack_chk_guard"):
                        canary = True
                    if sym.name.endswith("_chk"):
                        fortify = True

        # PIE: ET_DYN + a dynamic section with DT_FLAGS_1 PIE bit (already set),
        # or the soname/interpreter heuristic: ET_DYN with DT_NEEDED counts as PIE.
        if out["file_type"] == "DYN" and needed_libs:
            pie = True

    out["sections"] = sections
    out["imports"] = imports
    out["needed"] = needed_libs
    out["protection"] = {
        "nx_enabled": nx,
        "pie_enabled": pie,
        "relro": relro,
        "canary": canary,
        "fortify_source": fortify,
    }
    return out

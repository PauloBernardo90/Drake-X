"""Binary format detection for sample routing.

Identifies file format by magic bytes without executing the sample.
Used by the CLI and engine to route samples to the correct domain
engine (APK, PE, ELF).
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path


class BinaryFormat(StrEnum):
    PE = "pe"
    ELF = "elf"
    APK = "apk"
    MACHO = "macho"
    UNKNOWN = "unknown"


# Magic byte signatures
_PE_DOS_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
_APK_ZIP_MAGIC = b"PK\x03\x04"


def detect_format(path: Path) -> BinaryFormat:
    """Detect binary format from file magic bytes.

    Reads the first 64 bytes to identify format. Does not execute the
    file. Returns ``BinaryFormat.UNKNOWN`` for unrecognized formats.
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(64)
    except (OSError, IOError):
        return BinaryFormat.UNKNOWN

    if len(header) < 4:
        return BinaryFormat.UNKNOWN

    # ELF: 7f 45 4c 46
    if header[:4] == _ELF_MAGIC:
        return BinaryFormat.ELF

    # PE: MZ header (DOS stub), verify PE signature offset exists
    if header[:2] == _PE_DOS_MAGIC:
        # Read e_lfanew at offset 0x3C to confirm PE
        if len(header) >= 0x40:
            e_lfanew = int.from_bytes(header[0x3C:0x40], "little")
            if 0 < e_lfanew < 0x1000:
                return BinaryFormat.PE
        # Even without PE signature check, MZ is likely PE/DOS
        return BinaryFormat.PE

    # Mach-O (fat or thin)
    if header[:4] in _MACHO_MAGICS:
        return BinaryFormat.MACHO
    # Fat Mach-O (big-endian magic)
    if header[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        return BinaryFormat.MACHO

    # APK: ZIP with AndroidManifest.xml
    if header[:4] == _APK_ZIP_MAGIC:
        # Check if it looks like an APK (contains AndroidManifest.xml)
        try:
            with open(path, "rb") as fh:
                # Search first 8KB for AndroidManifest reference
                search_bytes = fh.read(8192)
                if b"AndroidManifest" in search_bytes:
                    return BinaryFormat.APK
        except (OSError, IOError):
            pass
        # ZIP but not APK — treat as unknown
        return BinaryFormat.UNKNOWN

    return BinaryFormat.UNKNOWN

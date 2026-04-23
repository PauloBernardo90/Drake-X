"""DEX file parser — extract structural metadata from raw DEX files.

This module reads the DEX binary header directly (no external tools needed)
to extract class/method/string counts, DEX version, and basic structural
information. It provides the foundational inventory that other analyzers
build upon.

Reference: https://source.android.com/docs/core/runtime/dex-format
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from ..logging import get_logger
from ..models.dex import DexFileInfo

log = get_logger("dex.parser")

# DEX magic: "dex\n" followed by version "035\0" or "037\0" etc.
_DEX_MAGIC = b"dex\n"
_HEADER_SIZE = 112  # Minimum DEX header size


def parse_dex_header(dex_path: Path) -> DexFileInfo | None:
    """Parse a DEX file header and return structural metadata.

    Returns ``None`` if the file is not a valid DEX or cannot be read.
    """
    path = Path(dex_path)
    if not path.is_file():
        log.warning("DEX file not found: %s", path)
        return None

    try:
        data = path.read_bytes()
    except OSError as exc:
        log.warning("Cannot read DEX file %s: %s", path, exc)
        return None

    if len(data) < _HEADER_SIZE:
        log.warning("File too small to be a DEX: %s (%d bytes)", path, len(data))
        return None

    if data[:4] != _DEX_MAGIC:
        log.warning("Not a DEX file (bad magic): %s", path)
        return None

    # Parse version string (e.g., "035\0")
    version_raw = data[4:8]
    dex_version = version_raw.rstrip(b"\x00").decode("ascii", errors="replace")

    # Parse header fields (little-endian)
    try:
        # Offsets from DEX format spec
        string_ids_size = struct.unpack_from("<I", data, 56)[0]
        type_ids_size = struct.unpack_from("<I", data, 64)[0]
        method_ids_size = struct.unpack_from("<I", data, 88)[0]
        class_defs_size = struct.unpack_from("<I", data, 96)[0]
    except struct.error:
        log.warning("Truncated DEX header: %s", path)
        return None

    sha256 = hashlib.sha256(data).hexdigest()

    return DexFileInfo(
        filename=path.name,
        path=str(path),
        size=len(data),
        sha256=sha256,
        class_count=class_defs_size,
        method_count=method_ids_size,
        string_count=string_ids_size,
        dex_version=dex_version,
    )


def extract_dex_strings(dex_path: Path) -> list[str]:
    """Extract string constants from a DEX file by reading the string table.

    This is a best-effort extraction — for full fidelity, use androguard.
    Returns an empty list if the file cannot be parsed.
    """
    path = Path(dex_path)
    try:
        data = path.read_bytes()
    except OSError:
        return []

    if len(data) < _HEADER_SIZE or data[:4] != _DEX_MAGIC:
        return []

    try:
        string_ids_size = struct.unpack_from("<I", data, 56)[0]
        string_ids_off = struct.unpack_from("<I", data, 60)[0]
    except struct.error:
        return []

    strings: list[str] = []
    for i in range(min(string_ids_size, 100_000)):  # safety cap
        try:
            str_data_off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            if str_data_off >= len(data):
                continue
            # ULEB128 length prefix — skip it
            pos = str_data_off
            while pos < len(data) and data[pos] & 0x80:
                pos += 1
            pos += 1  # skip last byte of ULEB128
            # Read MUTF-8 string until null
            end = data.find(b"\x00", pos)
            if end == -1:
                end = min(pos + 2048, len(data))
            raw = data[pos:end]
            strings.append(raw.decode("utf-8", errors="replace"))
        except (struct.error, IndexError):
            continue

    return strings


def is_dex_file(path: Path) -> bool:
    """Check if a file has a valid DEX magic header."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == _DEX_MAGIC
    except OSError:
        return False

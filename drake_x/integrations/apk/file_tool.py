"""file(1), md5sum, sha256sum wrappers for APK identification."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .runner import ToolOutput, run_tool


def identify_file(path: Path) -> ToolOutput:
    return run_tool("file", ["file", "-b", str(path)])


def compute_hashes(path: Path) -> dict[str, str]:
    """Compute MD5 and SHA-256 in Python (no subprocess dependency)."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

"""Streaming hash computation for samples and artifacts.

All hashing uses streaming reads (8 KiB chunks) to handle large files
without loading them entirely into memory. The primary identifier is
always SHA-256.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..logging import get_logger
from .exceptions import IntegrityError

log = get_logger("integrity.hashing")

_CHUNK_SIZE = 8192


@dataclass(frozen=True)
class SampleIdentity:
    """Immutable identity of a file based on its cryptographic hashes.

    SHA-256 is the primary identifier. MD5 and SHA-1 are included for
    compatibility with external systems (VirusTotal, YARA, etc.).
    """

    file_name: str
    file_size: int
    md5: str
    sha1: str
    sha256: str

    @property
    def short_id(self) -> str:
        """Short display identifier (first 12 chars of SHA-256)."""
        return self.sha256[:12]

    def to_dict(self) -> dict[str, str | int]:
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
        }


def compute_file_hashes(path: Path) -> SampleIdentity:
    """Compute MD5, SHA-1, and SHA-256 of a file via streaming reads.

    Parameters
    ----------
    path:
        Path to the file to hash.

    Returns
    -------
    SampleIdentity with all three hashes and file metadata.

    Raises
    ------
    IntegrityError:
        If the file cannot be read.
    """
    path = Path(path).resolve()

    if not path.is_file():
        raise IntegrityError(f"Cannot hash: not a file: {path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        file_size = path.stat().st_size
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except OSError as exc:
        raise IntegrityError(f"Cannot read file for hashing: {exc}") from exc

    identity = SampleIdentity(
        file_name=path.name,
        file_size=file_size,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )

    log.info(
        "Hashed %s: SHA-256=%s (%d bytes)",
        identity.file_name, identity.short_id, identity.file_size,
    )
    return identity


def compute_sha256(path: Path) -> str:
    """Compute only SHA-256 of a file (fast path for verification)."""
    path = Path(path).resolve()
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
                h.update(chunk)
    except OSError as exc:
        raise IntegrityError(f"Cannot read file: {exc}") from exc
    return h.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 of in-memory bytes (for reports, JSON, etc.)."""
    return hashlib.sha256(data).hexdigest()

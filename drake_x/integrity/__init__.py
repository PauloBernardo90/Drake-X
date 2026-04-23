"""Integrity, provenance, and chain-of-custody layer for Drake-X.

Core principle: **No evidence exists without a hash. No result exists
without a reference to the original hash.**

This package provides:

- Streaming hash computation (MD5, SHA-1, SHA-256)
- Sample identity tracking
- Chain-of-custody event log
- Artifact integrity registration
- Pipeline and tool versioning
- Integrity verification with fail-closed semantics
- Structured integrity reports
"""

from .hashing import compute_file_hashes, SampleIdentity
from .chain import CustodyChain
from .verifier import IntegrityVerifier

__all__ = ["compute_file_hashes", "SampleIdentity", "CustodyChain", "IntegrityVerifier"]

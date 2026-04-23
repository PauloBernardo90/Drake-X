"""GPG signing for integrity reports.

Provides detached-signature support for integrity reports using gpg.
Signing is **optional** and requires gpg to be installed with a signing key
available in the operator's keychain.

Design principles:
- Signing is strictly optional — missing gpg does not break the pipeline
- Detached signatures (.asc) preserve the original JSON for tamper detection
- Signing records the key fingerprint used
- Verification is a separate, local operation (no online calls)
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..logging import get_logger
from .exceptions import IntegrityError

log = get_logger("integrity.signing")

GPG_BINARY = "gpg"


@dataclass(frozen=True)
class SignatureResult:
    """Outcome of a signing operation."""
    signed: bool
    signature_path: str = ""
    key_fingerprint: str = ""
    error: str = ""


def is_gpg_available() -> bool:
    """Check if gpg binary is available."""
    return shutil.which(GPG_BINARY) is not None


def sign_file(
    file_path: Path,
    *,
    key_id: str = "",
    output_path: Path | None = None,
) -> SignatureResult:
    """Produce a detached ASCII-armored signature for a file.

    Parameters
    ----------
    file_path:
        The file to sign (e.g., integrity_report.json).
    key_id:
        Optional GPG key ID or fingerprint. If empty, uses default key.
    output_path:
        Optional output path (defaults to ``<file>.asc``).

    Returns
    -------
    SignatureResult with signed=True on success.
    """
    path = Path(file_path).resolve()

    if not path.is_file():
        return SignatureResult(
            signed=False,
            error=f"File not found: {path}",
        )

    if not is_gpg_available():
        return SignatureResult(
            signed=False,
            error="gpg not installed — signing skipped",
        )

    sig_path = Path(output_path) if output_path else path.with_suffix(path.suffix + ".asc")

    cmd = [
        GPG_BINARY,
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--output", str(sig_path),
    ]
    if key_id:
        cmd.extend(["--local-user", key_id])
    cmd.append(str(path))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return SignatureResult(
            signed=False,
            error="gpg signing timed out",
        )
    except (FileNotFoundError, OSError) as exc:
        return SignatureResult(
            signed=False,
            error=f"gpg exec error: {exc}",
        )

    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")[:300]
        return SignatureResult(
            signed=False,
            error=f"gpg signing failed: {err}",
        )

    # Extract the key fingerprint used
    fingerprint = _extract_key_fingerprint(proc.stderr.decode("utf-8", errors="replace"))

    log.info("Signed %s with key %s", path.name, fingerprint or "default")

    return SignatureResult(
        signed=True,
        signature_path=str(sig_path),
        key_fingerprint=fingerprint,
    )


def verify_signature(
    file_path: Path,
    signature_path: Path,
) -> tuple[bool, str]:
    """Verify a detached signature against a file.

    Returns
    -------
    (verified, details) — verified=True on successful verification,
    details contains the key ID / signer information or error message.
    """
    if not is_gpg_available():
        return False, "gpg not installed"

    file_path = Path(file_path).resolve()
    sig_path = Path(signature_path).resolve()

    if not file_path.is_file() or not sig_path.is_file():
        return False, "file or signature not found"

    try:
        proc = subprocess.run(
            [GPG_BINARY, "--batch", "--verify", str(sig_path), str(file_path)],
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False, "gpg verification timed out"
    except (FileNotFoundError, OSError) as exc:
        return False, f"gpg exec error: {exc}"

    stderr = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode == 0:
        # Extract signer info from stderr (gpg prints verification info there)
        details = _extract_signer_info(stderr)
        return True, details

    return False, f"signature verification failed: {stderr[:300]}"


def _extract_key_fingerprint(stderr: str) -> str:
    """Extract the key fingerprint from gpg stderr output."""
    # gpg --status-fd would be more reliable, but we parse stderr for simplicity
    for line in stderr.splitlines():
        if "key ID" in line or "using" in line.lower():
            # Best-effort: keep the last hex token
            tokens = line.split()
            for tok in tokens:
                if len(tok) >= 16 and all(c in "0123456789ABCDEFabcdef" for c in tok):
                    return tok.upper()
    return ""


def _extract_signer_info(stderr: str) -> str:
    """Extract signer information from gpg --verify output."""
    for line in stderr.splitlines():
        if line.startswith("gpg: Good signature"):
            return line.replace("gpg: ", "").strip()[:200]
    return "signature verified (signer details not parsed)"

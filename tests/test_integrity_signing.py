"""Tests for drake_x.integrity.signing — GPG signing support."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drake_x.integrity.signing import (
    SignatureResult,
    is_gpg_available,
    sign_file,
    verify_signature,
)


class TestIsGpgAvailable:
    def test_available(self) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            assert is_gpg_available() is True

    def test_unavailable(self) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value=None):
            assert is_gpg_available() is False


class TestSignFile:
    def test_graceful_when_gpg_missing(self, tmp_path: Path) -> None:
        f = tmp_path / "report.json"
        f.write_text("{}")
        with patch("drake_x.integrity.signing.shutil.which", return_value=None):
            result = sign_file(f)
            assert result.signed is False
            assert "not installed" in result.error

    def test_missing_file(self, tmp_path: Path) -> None:
        result = sign_file(tmp_path / "nonexistent.json")
        assert result.signed is False
        assert "not found" in result.error

    def test_successful_signing(self, tmp_path: Path) -> None:
        f = tmp_path / "report.json"
        f.write_text("{}")
        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            with patch("drake_x.integrity.signing.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stderr=b"gpg: using key 1234567890ABCDEF\n",
                )
                result = sign_file(f, key_id="test-key")
                assert result.signed is True
                assert result.signature_path.endswith(".asc")

    def test_signing_failure(self, tmp_path: Path) -> None:
        f = tmp_path / "report.json"
        f.write_text("{}")
        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            with patch("drake_x.integrity.signing.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=2,
                    stderr=b"gpg: no secret key",
                )
                result = sign_file(f)
                assert result.signed is False
                assert "failed" in result.error

    def test_custom_output_path(self, tmp_path: Path) -> None:
        f = tmp_path / "report.json"
        f.write_text("{}")
        custom_sig = tmp_path / "custom.sig"

        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            with patch("drake_x.integrity.signing.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr=b"")
                result = sign_file(f, output_path=custom_sig)
                assert result.signed is True
                # Verify --output was set to custom_sig
                cmd = mock_run.call_args[0][0]
                assert str(custom_sig) in cmd


class TestVerifySignature:
    def test_gpg_missing(self, tmp_path: Path) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value=None):
            ok, details = verify_signature(tmp_path / "a", tmp_path / "b")
            assert ok is False

    def test_missing_files(self, tmp_path: Path) -> None:
        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            ok, details = verify_signature(tmp_path / "missing", tmp_path / "also_missing")
            assert ok is False

    def test_successful_verification(self, tmp_path: Path) -> None:
        f = tmp_path / "report.json"
        sig = tmp_path / "report.json.asc"
        f.write_text("{}")
        sig.write_text("-----BEGIN PGP SIGNATURE-----\n...\n")

        with patch("drake_x.integrity.signing.shutil.which", return_value="/usr/bin/gpg"):
            with patch("drake_x.integrity.signing.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stderr=b'gpg: Good signature from "Test User <t@example.com>"\n',
                )
                ok, details = verify_signature(f, sig)
                assert ok is True
                assert "Good signature" in details

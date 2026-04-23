"""Tests for drake_x.dex.parser — DEX binary header parsing."""

from __future__ import annotations

import hashlib
import struct
import tempfile
from pathlib import Path

import pytest

from drake_x.dex.parser import extract_dex_strings, is_dex_file, parse_dex_header


def _make_dex_bytes(
    *,
    version: bytes = b"035\x00",
    string_ids_size: int = 100,
    string_ids_off: int = 112,
    type_ids_size: int = 50,
    type_ids_off: int = 200,
    method_ids_size: int = 80,
    method_ids_off: int = 300,
    class_defs_size: int = 20,
    class_defs_off: int = 400,
) -> bytes:
    """Build a minimal synthetic DEX header (112 bytes)."""
    buf = bytearray(512)
    # Magic
    buf[0:4] = b"dex\n"
    buf[4:8] = version
    # String IDs
    struct.pack_into("<I", buf, 56, string_ids_size)
    struct.pack_into("<I", buf, 60, string_ids_off)
    # Type IDs
    struct.pack_into("<I", buf, 64, type_ids_size)
    struct.pack_into("<I", buf, 68, type_ids_off)
    # Method IDs
    struct.pack_into("<I", buf, 88, method_ids_size)
    struct.pack_into("<I", buf, 92, method_ids_off)
    # Class defs
    struct.pack_into("<I", buf, 96, class_defs_size)
    struct.pack_into("<I", buf, 100, class_defs_off)
    return bytes(buf)


@pytest.fixture
def dex_file(tmp_path: Path) -> Path:
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_make_dex_bytes())
    return dex


@pytest.fixture
def non_dex_file(tmp_path: Path) -> Path:
    f = tmp_path / "not_a_dex.bin"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    return f


class TestParseDexHeader:
    def test_valid_dex(self, dex_file: Path) -> None:
        info = parse_dex_header(dex_file)
        assert info is not None
        assert info.filename == "classes.dex"
        assert info.class_count == 20
        assert info.method_count == 80
        assert info.string_count == 100
        assert info.dex_version == "035"
        assert info.size == 512
        assert len(info.sha256) == 64

    def test_non_dex_returns_none(self, non_dex_file: Path) -> None:
        assert parse_dex_header(non_dex_file) is None

    def test_missing_file(self, tmp_path: Path) -> None:
        assert parse_dex_header(tmp_path / "missing.dex") is None

    def test_small_file(self, tmp_path: Path) -> None:
        f = tmp_path / "tiny.dex"
        f.write_bytes(b"dex\n" + b"\x00" * 10)
        assert parse_dex_header(f) is None

    def test_different_version(self, tmp_path: Path) -> None:
        dex = tmp_path / "classes.dex"
        dex.write_bytes(_make_dex_bytes(version=b"037\x00"))
        info = parse_dex_header(dex)
        assert info is not None
        assert info.dex_version == "037"


class TestIsDexFile:
    def test_valid(self, dex_file: Path) -> None:
        assert is_dex_file(dex_file) is True

    def test_invalid(self, non_dex_file: Path) -> None:
        assert is_dex_file(non_dex_file) is False

    def test_missing(self, tmp_path: Path) -> None:
        assert is_dex_file(tmp_path / "nope.dex") is False


class TestExtractDexStrings:
    def test_non_dex_returns_empty(self, non_dex_file: Path) -> None:
        assert extract_dex_strings(non_dex_file) == []

    def test_missing_file(self, tmp_path: Path) -> None:
        assert extract_dex_strings(tmp_path / "gone.dex") == []

"""Tests for drake_x.integrity.hashing — streaming hash computation."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from drake_x.integrity.exceptions import IntegrityError
from drake_x.integrity.hashing import (
    SampleIdentity,
    compute_file_hashes,
    compute_sha256,
    hash_bytes,
)


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "test_sample.apk"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    return f


@pytest.fixture
def known_content_file(tmp_path: Path) -> Path:
    content = b"Drake-X integrity test content"
    f = tmp_path / "known.bin"
    f.write_bytes(content)
    return f


class TestComputeFileHashes:
    def test_computes_all_three_hashes(self, sample_file: Path) -> None:
        identity = compute_file_hashes(sample_file)
        assert len(identity.md5) == 32
        assert len(identity.sha1) == 40
        assert len(identity.sha256) == 64

    def test_sha256_is_correct(self, known_content_file: Path) -> None:
        content = known_content_file.read_bytes()
        expected = hashlib.sha256(content).hexdigest()
        identity = compute_file_hashes(known_content_file)
        assert identity.sha256 == expected

    def test_md5_is_correct(self, known_content_file: Path) -> None:
        content = known_content_file.read_bytes()
        expected = hashlib.md5(content).hexdigest()
        identity = compute_file_hashes(known_content_file)
        assert identity.md5 == expected

    def test_sha1_is_correct(self, known_content_file: Path) -> None:
        content = known_content_file.read_bytes()
        expected = hashlib.sha1(content).hexdigest()
        identity = compute_file_hashes(known_content_file)
        assert identity.sha1 == expected

    def test_same_file_same_hash(self, sample_file: Path) -> None:
        h1 = compute_file_hashes(sample_file)
        h2 = compute_file_hashes(sample_file)
        assert h1.sha256 == h2.sha256
        assert h1.md5 == h2.md5
        assert h1.sha1 == h2.sha1

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.bin"
        f2 = tmp_path / "file2.bin"
        f1.write_bytes(b"content A")
        f2.write_bytes(b"content B")
        h1 = compute_file_hashes(f1)
        h2 = compute_file_hashes(f2)
        assert h1.sha256 != h2.sha256

    def test_one_byte_change(self, tmp_path: Path) -> None:
        f1 = tmp_path / "original.bin"
        f2 = tmp_path / "modified.bin"
        data = b"A" * 1000
        f1.write_bytes(data)
        f2.write_bytes(data[:500] + b"B" + data[501:])
        h1 = compute_file_hashes(f1)
        h2 = compute_file_hashes(f2)
        assert h1.sha256 != h2.sha256

    def test_file_metadata(self, sample_file: Path) -> None:
        identity = compute_file_hashes(sample_file)
        assert identity.file_name == "test_sample.apk"
        assert identity.file_size == 204  # 4 + 200

    def test_short_id(self, sample_file: Path) -> None:
        identity = compute_file_hashes(sample_file)
        assert identity.short_id == identity.sha256[:12]

    def test_to_dict(self, sample_file: Path) -> None:
        identity = compute_file_hashes(sample_file)
        d = identity.to_dict()
        assert d["file_name"] == "test_sample.apk"
        assert "sha256" in d
        assert "md5" in d
        assert "sha1" in d

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IntegrityError, match="not a file"):
            compute_file_hashes(tmp_path / "nonexistent.bin")

    def test_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IntegrityError, match="not a file"):
            compute_file_hashes(tmp_path)


class TestComputeSha256:
    def test_matches_full_hash(self, sample_file: Path) -> None:
        full = compute_file_hashes(sample_file)
        quick = compute_sha256(sample_file)
        assert quick == full.sha256


class TestHashBytes:
    def test_correct(self) -> None:
        data = b"test data"
        expected = hashlib.sha256(data).hexdigest()
        assert hash_bytes(data) == expected

    def test_empty(self) -> None:
        expected = hashlib.sha256(b"").hexdigest()
        assert hash_bytes(b"") == expected

"""Tests for bounded shellcode decoding (v0.9)."""

from __future__ import annotations

from drake_x.integrations.exploit.shellcode_decode import bounded_decode


def test_xor_single_detects_pe_header():
    key = 0x41
    mz = b"MZ" + b"\x90" * 30
    encoded = bytes(b ^ key for b in mz)

    results = bounded_decode(encoded, source_ref="test_section")
    assert len(results) >= 1
    assert any("PE executable" in r.classification_hint for r in results)
    assert all(r.partial for r in results)
    assert all("bounded" in r.caveats[0].lower() for r in results)


def test_xor_single_detects_elf_header():
    key = 0x55
    elf = b"\x7fELF" + b"\x00" * 28
    encoded = bytes(b ^ key for b in elf)

    results = bounded_decode(encoded, source_ref="test")
    assert any("ELF executable" in r.classification_hint for r in results)


def test_base64_decoding():
    import base64
    payload = b"MZ" + b"\x90" * 30
    encoded = base64.b64encode(payload)

    results = bounded_decode(encoded, source_ref="test", methods=["base64"])
    assert len(results) >= 1
    assert results[0].classification_hint == "PE executable header"
    assert "bounded" in results[0].caveats[0].lower()


def test_empty_blob_returns_nothing():
    assert bounded_decode(b"", source_ref="test") == []
    assert bounded_decode(b"\x00" * 4, source_ref="test") == []


def test_random_data_returns_nothing():
    import os
    random_data = os.urandom(256)
    results = bounded_decode(random_data, source_ref="test", methods=["xor_single"])
    # Random data should not produce false PE/ELF matches
    pe_elf = [r for r in results if "executable" in r.classification_hint.lower()]
    assert len(pe_elf) == 0


def test_decoded_output_bounded():
    key = 0x41
    large = b"MZ" + b"\x90" * 8000
    encoded = bytes(b ^ key for b in large)

    results = bounded_decode(encoded, source_ref="test")
    for r in results:
        assert r.decoded_size <= 1024  # _MAX_OUTPUT_BYTES


def test_caveats_never_operational():
    key = 0x41
    mz = b"MZ" + b"\x90" * 30
    encoded = bytes(b ^ key for b in mz)

    results = bounded_decode(encoded, source_ref="test")
    forbidden = ["execute the", "run the payload", "weaponize", "payload ready"]
    for r in results:
        text = " ".join(r.caveats).lower()
        for word in forbidden:
            assert word not in text, f"Operational language '{word}' in caveats"

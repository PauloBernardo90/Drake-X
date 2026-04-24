"""Unit tests for drake_x.integrations.binary.string_extractor (v1.2)."""

from __future__ import annotations


def test_ascii_extraction():
    from drake_x.integrations.binary.string_extractor import extract_strings
    data = b"\x00\x01hello\x00\x02world_longer_str\x00"
    out = extract_strings(data)
    assert "hello" in out
    assert "world_longer_str" in out


def test_utf16_extraction():
    from drake_x.integrations.binary.string_extractor import extract_strings
    # "CryptEncrypt" in UTF-16LE followed by a padding byte
    payload = "CryptEncrypt".encode("utf-16-le") + b"\x00\x00"
    data = b"\x00" * 16 + payload + b"\x00" * 16
    out = extract_strings(data)
    assert "CryptEncrypt" in out


def test_classification_url():
    from drake_x.integrations.binary.string_extractor import classify_string
    assert classify_string("https://evil.com/c2?q=1") == "url"


def test_classification_ip():
    from drake_x.integrations.binary.string_extractor import classify_string
    assert classify_string("198.51.100.42") == "ip"
    assert classify_string("198.51.100.42:8443") == "ip"


def test_classification_ransom_extension():
    from drake_x.integrations.binary.string_extractor import classify_string
    assert classify_string(".WNCRY extension marker") == "ransom_extension"
    assert classify_string(".locked ") == "ransom_extension"


def test_classification_anti_recovery():
    from drake_x.integrations.binary.string_extractor import classify_string
    assert (classify_string("vssadmin delete shadows /all /quiet")
            == "anti_recovery_vssadmin")


def test_classification_sensitive_api():
    from drake_x.integrations.binary.string_extractor import classify_string
    assert classify_string("CryptEncrypt") == "sensitive_api_crypto"
    assert classify_string("CreateRemoteThread") == "sensitive_api_injection"
    assert classify_string("SetWindowsHookExA") == "sensitive_api_surveillance"
    # non-API strings must NOT be classified as sensitive_api
    assert classify_string("Setup") is None
    assert classify_string("hello world") is None


def test_indirect_api_detection():
    from drake_x.integrations.binary.string_extractor import (
        extract_tagged_strings, detect_dynamic_api_resolution,
    )
    # WannaCry-style: 'CryptEncrypt' appears as ASCII string but is NOT
    # in the static import table (it is resolved dynamically).
    data = b"CryptEncrypt\x00" + b"x" * 200
    tagged = extract_tagged_strings(data, existing_imports=set())
    assert any(r["value"] == "CryptEncrypt" for r in tagged)
    finding = detect_dynamic_api_resolution(tagged)
    assert len(finding) >= 1
    assert finding[0]["api_name"] == "CryptEncrypt"
    assert finding[0]["category"] == "sensitive_api_crypto"
    assert "dynamic resolution" in finding[0]["rationale"]


def test_indirect_api_NOT_flagged_when_imported():
    """If the sensitive API is already in the import table, it is NOT
    counted as a dynamic-resolution indicator."""
    from drake_x.integrations.binary.string_extractor import (
        extract_tagged_strings, detect_dynamic_api_resolution,
    )
    data = b"CryptEncrypt\x00" + b"x" * 200
    tagged = extract_tagged_strings(data, existing_imports={"CryptEncrypt"})
    # The string is still tagged, but 'indirect_api' is False and no
    # dynamic-resolution finding is emitted.
    dyn = detect_dynamic_api_resolution(tagged)
    assert dyn == []

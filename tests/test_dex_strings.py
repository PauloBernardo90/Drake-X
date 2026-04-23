"""Tests for drake_x.dex.strings — string classification."""

from __future__ import annotations

import pytest

from drake_x.dex.strings import classify_strings
from drake_x.models.dex import StringCategory


class TestClassifyStrings:
    def test_url_detection(self) -> None:
        strings = ["https://evil.example.com/gate.php", "hello world"]
        results = classify_strings(strings)
        urls = [r for r in results if r.category == StringCategory.URL]
        assert len(urls) >= 1
        assert urls[0].is_potential_ioc

    def test_ip_detection(self) -> None:
        strings = ["45.33.32.156"]
        results = classify_strings(strings)
        ips = [r for r in results if r.category == StringCategory.IP]
        assert len(ips) == 1
        assert ips[0].is_potential_ioc

    def test_private_ip_filtered(self) -> None:
        strings = ["192.168.1.1", "10.0.0.1", "127.0.0.1"]
        results = classify_strings(strings)
        ips = [r for r in results if r.category == StringCategory.IP]
        assert len(ips) == 0

    def test_domain_detection(self) -> None:
        strings = ["malware-c2.xyz"]
        results = classify_strings(strings)
        domains = [r for r in results if r.category == StringCategory.DOMAIN]
        assert len(domains) == 1

    def test_phishing_detection(self) -> None:
        strings = ["Enter your card number and CVV"]
        results = classify_strings(strings)
        phishing = [r for r in results if r.category == StringCategory.PHISHING]
        assert len(phishing) >= 1

    def test_c2_indicator(self) -> None:
        strings = ["/gate.php?id=123&cmd=upload"]
        results = classify_strings(strings)
        c2 = [r for r in results if r.category == StringCategory.C2_INDICATOR]
        assert len(c2) >= 1

    def test_base64_blob(self) -> None:
        strings = ["SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nIGJhc2U2NCBibG9i"]
        results = classify_strings(strings)
        blobs = [r for r in results if r.category == StringCategory.ENCODED_BLOB]
        assert len(blobs) == 1

    def test_package_target(self) -> None:
        # Must match _PACKAGE_RE and not match domain regex first
        strings = ["com.targetbank.trojan.v2"]
        results = classify_strings(strings)
        pkgs = [r for r in results if r.category == StringCategory.PACKAGE_TARGET]
        assert len(pkgs) == 1

    def test_filesystem_path(self) -> None:
        # Path must start with /data/, /sdcard/, etc.
        strings = ["/data/local/tmp/payload.dex"]
        results = classify_strings(strings)
        paths = [r for r in results if r.category == StringCategory.FILESYSTEM_PATH]
        assert len(paths) == 1

    def test_command_detection(self) -> None:
        strings = ["chmod 755 /data/local/tmp/exploit"]
        results = classify_strings(strings)
        cmds = [r for r in results if r.category == StringCategory.COMMAND]
        assert len(cmds) >= 1

    def test_noise_filtered(self) -> None:
        strings = ["android.intent.action.MAIN", "a", "bb", "ccc"]
        results = classify_strings(strings)
        # Short strings should be filtered
        assert all(r.value not in ("a", "bb", "ccc") for r in results)

    def test_framework_package_filtered(self) -> None:
        strings = ["android.widget.TextView", "androidx.core.app.ActivityCompat"]
        results = classify_strings(strings)
        pkgs = [r for r in results if r.category == StringCategory.PACKAGE_TARGET]
        assert len(pkgs) == 0

    def test_empty_input(self) -> None:
        assert classify_strings([]) == []

    def test_dedup(self) -> None:
        strings = ["https://evil.com/api", "https://evil.com/api", "https://evil.com/api"]
        results = classify_strings(strings)
        assert len(results) == 1

    def test_source_dex_propagated(self) -> None:
        strings = ["https://c2.example.org/beacon"]
        results = classify_strings(strings, source_dex="classes2.dex")
        assert results[0].source_dex == "classes2.dex"

    def test_crypto_detection(self) -> None:
        strings = ["AES/CBC/PKCS5Padding"]
        results = classify_strings(strings)
        crypto = [r for r in results if r.category == StringCategory.CRYPTO]
        assert len(crypto) >= 1

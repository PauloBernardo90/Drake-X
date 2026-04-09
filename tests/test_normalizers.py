"""Normalizer tests with representative tool output."""

from __future__ import annotations

from datetime import UTC, datetime

from drake_x.models.tool_result import ToolResult, ToolResultStatus
from drake_x.normalize import (
    normalize_curl,
    normalize_dig,
    normalize_nikto,
    normalize_nmap,
    normalize_sslscan,
    normalize_whatweb,
    normalize_whois,
)
from drake_x.normalize.common import normalize_result


def _make_result(name: str, stdout: str = "", stderr: str = "", status=ToolResultStatus.OK) -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        stdout=stdout,
        stderr=stderr,
        status=status,
        exit_code=0 if status == ToolResultStatus.OK else 1,
        finished_at=datetime.now(UTC),
        duration_seconds=0.1,
    )


# ----- nmap ------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_normalize_nmap_extracts_open_ports() -> None:
    art = normalize_nmap(_make_result("nmap", NMAP_XML))
    assert art.kind == "nmap.ports"
    assert len(art.payload["hosts"]) == 1
    host = art.payload["hosts"][0]
    open_ports = host["open_ports"]
    assert {p["port"] for p in open_ports} == {80, 443}
    assert any(p["product"] == "nginx" for p in open_ports)
    assert art.payload["open_port_count"] == 2
    assert art.confidence > 0.5


def test_normalize_nmap_handles_garbage() -> None:
    art = normalize_nmap(_make_result("nmap", "<<not xml"))
    assert art.confidence == 0.0
    assert art.kind in {"nmap.unparsed", "nmap.ports"}


def test_normalize_nmap_handles_empty() -> None:
    art = normalize_nmap(_make_result("nmap", ""))
    assert art.payload["hosts"] == []
    assert art.confidence == 0.0


# ----- dig -------------------------------------------------------------------

DIG_OUTPUT = """example.com.		300	IN	A	93.184.216.34
example.com.		300	IN	A	93.184.216.35
example.com.		300	IN	NS	a.iana-servers.net.
example.com.		300	IN	NS	b.iana-servers.net.
example.com.		300	IN	MX	0 .
example.com.		300	IN	TXT	"v=spf1 -all"
"""


def test_normalize_dig() -> None:
    art = normalize_dig(_make_result("dig", DIG_OUTPUT))
    records = art.payload["records"]
    assert "A" in records
    assert "93.184.216.34" in records["A"]
    assert "NS" in records
    assert len(records["NS"]) == 2
    assert art.confidence > 0.5


def test_normalize_dig_empty() -> None:
    art = normalize_dig(_make_result("dig", ""))
    assert art.confidence == 0.0


# ----- whois -----------------------------------------------------------------

WHOIS_OUTPUT = """Domain Name: EXAMPLE.COM
Registrar: ICANN
Updated Date: 2023-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Registrant Country: US
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
"""


def test_normalize_whois() -> None:
    art = normalize_whois(_make_result("whois", WHOIS_OUTPUT))
    payload = art.payload
    assert payload["registrar"] == "ICANN"
    assert payload["country"] == "US"
    assert "a.iana-servers.net" in payload["nameservers"]
    assert art.confidence > 0.5


def test_normalize_whois_unknown_format() -> None:
    art = normalize_whois(_make_result("whois", "completely unstructured blob"))
    assert art.confidence < 0.5


# ----- curl ------------------------------------------------------------------

CURL_OUTPUT = """HTTP/1.1 301 Moved Permanently
Location: https://example.com/
Content-Type: text/html

HTTP/2 200
server: nginx
content-type: text/html
strict-transport-security: max-age=63072000

"""


def test_normalize_curl() -> None:
    art = normalize_curl(_make_result("curl", CURL_OUTPUT))
    assert art.payload["final_status"] == 200
    assert art.payload["final_headers"].get("server") == "nginx"
    assert art.payload["redirect_chain"] == ["https://example.com/"]


def test_normalize_curl_empty() -> None:
    art = normalize_curl(_make_result("curl", ""))
    assert art.payload["final_status"] is None


# ----- whatweb ---------------------------------------------------------------

WHATWEB_OUTPUT = """{"target":"http://example.com","plugins":{"nginx":{"version":["1.18.0"]},"HTML5":{},"PHP":{"version":["8.1.0"]}}}"""


def test_normalize_whatweb() -> None:
    art = normalize_whatweb(_make_result("whatweb", WHATWEB_OUTPUT))
    techs = art.payload["technologies"]
    assert any("nginx" in t for t in techs)
    assert any("PHP" in t for t in techs)
    assert art.payload["plugin_count"] == 3


def test_normalize_whatweb_garbage() -> None:
    art = normalize_whatweb(_make_result("whatweb", "not json"))
    assert art.confidence < 0.5


# ----- nikto -----------------------------------------------------------------

NIKTO_OUTPUT = """- Nikto v2.1.6
+ Server: nginx
+ The X-Content-Type-Options header is not set.
+ The X-XSS-Protection header is not defined.
+ Possible SQL Injection at /search?q=1 — try payload UNION SELECT
+ Server may leak inodes via ETags
"""


def test_normalize_nikto_strips_exploit_lines() -> None:
    art = normalize_nikto(_make_result("nikto", NIKTO_OUTPUT))
    findings = art.payload["headline_findings"]
    assert any("X-Content-Type-Options" in f for f in findings)
    # The SQL injection line MUST be suppressed.
    assert not any("SQL Injection" in f for f in findings)
    assert art.payload["suppressed_exploit_suggestions"] >= 1


# ----- sslscan ---------------------------------------------------------------

SSLSCAN_OUTPUT = """Testing SSL server example.com on port 443

  SSLv2     disabled
  SSLv3     disabled
  TLSv1.0   enabled
  TLSv1.1   enabled
  TLSv1.2   enabled
  TLSv1.3   enabled

Accepted  TLSv1.2  128 bits  RC4-SHA
Subject:  example.com
Issuer:   DigiCert
Not valid before: Jan 1 00:00:00 2024 GMT
Not valid after:  Jan 1 00:00:00 2025 GMT
"""


def test_normalize_sslscan_detects_deprecated_protocols() -> None:
    art = normalize_sslscan(_make_result("sslscan", SSLSCAN_OUTPUT))
    payload = art.payload
    assert "TLSv1.0" in payload["enabled_protocols"]
    assert "TLSv1.0" in payload["deprecated_enabled"]
    assert any("RC4" in line for line in payload["weak_cipher_lines"])
    assert payload["certificate"]["subject"] == "example.com"


# ----- dispatch --------------------------------------------------------------


def test_normalize_result_dispatches_by_tool_name() -> None:
    art = normalize_result(_make_result("dig", DIG_OUTPUT))
    assert art is not None
    assert art.kind == "dns.records"


def test_normalize_result_skips_not_installed() -> None:
    r = _make_result("dig", "", status=ToolResultStatus.NOT_INSTALLED)
    assert normalize_result(r) is None


def test_normalize_result_unknown_tool() -> None:
    assert normalize_result(_make_result("mystery", "blob")) is None


# ----- NONZERO provenance ----------------------------------------------------


def test_nonzero_result_is_normalized_but_marked_degraded() -> None:
    result = _make_result("dig", DIG_OUTPUT, status=ToolResultStatus.NONZERO)
    result.exit_code = 9
    art = normalize_result(result)
    assert art is not None
    assert art.tool_status == "nonzero"
    assert art.exit_code == 9
    assert art.degraded is True
    # Confidence must be reduced compared to a clean run.
    clean = normalize_result(_make_result("dig", DIG_OUTPUT))
    assert art.confidence < clean.confidence
    assert any("degraded execution" in n for n in art.notes)


def test_ok_result_is_not_marked_degraded() -> None:
    art = normalize_result(_make_result("dig", DIG_OUTPUT))
    assert art is not None
    assert art.tool_status == "ok"
    assert art.degraded is False
    assert all("degraded execution" not in n for n in art.notes)


def test_nonzero_result_with_empty_stdout_is_skipped() -> None:
    result = _make_result("dig", "", status=ToolResultStatus.NONZERO)
    assert normalize_result(result) is None

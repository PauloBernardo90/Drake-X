"""Printable-string extractor for PE binaries (v1.2).

Drake-X's PE parser previously did not surface free strings from the
binary into the evidence graph. This meant that ransomware indicators
carried as string literals (``.WNCRY`` extensions, ``vssadmin delete
shadows`` commands, dynamically-resolved crypto API names like
``CryptEncrypt``) were invisible to both the rule-based baseline and
the LLM correlation layer.

This module fills the gap:

- :func:`extract_strings` pulls printable ASCII (≥4 chars) and
  UTF-16LE runs from raw PE bytes.
- :func:`extract_tagged_strings` classifies each string into a small
  set of categories (URL, IP, domain, email, onion, ransom_extension,
  anti_recovery_*, shell_command, sensitive_api_*, registry_run_key).
- :func:`detect_dynamic_api_resolution` flags sensitive API names that
  appear as string literals but are NOT in the static import table —
  a strong indicator of dynamic resolution via ``GetProcAddress``.

Outputs of this module are consumed by
:mod:`drake_x.modules.pe_analyze` and made available as
``PeAnalysisResult.strings`` and
``PeAnalysisResult.dynamic_api_resolution``. The rule-based baseline
correlator (``scripts/rules_baseline.yaml``) fires on them directly.

References: Windows ransomware reversal notes documenting that
WannaCry, Conti, and LockBit all resolve their crypto primitives via
``GetProcAddress`` and embed the API names as strings rather than as
static imports.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Low-level string extraction
# ---------------------------------------------------------------------------

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
# UTF-16LE run: each printable char followed by a NUL byte, at least 4 times.
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

MIN_LEN = 4
RAW_STRING_CAP = 20000
TAGGED_STRING_CAP = 500


def extract_strings(data: bytes,
                    *,
                    min_len: int = MIN_LEN,
                    cap: int = RAW_STRING_CAP) -> list[str]:
    """Extract printable ASCII + UTF-16LE strings from *data*.

    Returns a deduplicated list preserving first-occurrence order. The
    cap prevents pathological runaway on samples with heavy string
    tables; 20 000 is well above what any practical malware analysis
    needs and still bounded for memory.
    """
    seen: set[str] = set()
    out: list[str] = []

    for m in _ASCII_RE.finditer(data):
        s = m.group(0).decode("ascii", errors="replace")
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= cap:
                return out

    for m in _UTF16_RE.finditer(data):
        b = m.group(0)
        try:
            s = b.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            continue
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= cap:
                return out

    return out


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# (category, regex) — the first match wins. Anchored where meaningful,
# unanchored for substring-style categories (anti_recovery, registry).
_CATEGORY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("url",
     re.compile(r"https?://[A-Za-z0-9.\-/_%?#&=+:,@!~$*'()]+",
                re.IGNORECASE)),
    ("ip",
     re.compile(r"^\s*(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\s*$")),
    ("onion",
     re.compile(r"[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)),
    ("email",
     re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")),
    ("domain",
     re.compile(
         r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
         r"(?:com|net|org|ru|cn|info|biz|top|xyz|io|co|uk|tk|cc|me|pw|be|de|fr)$",
         re.IGNORECASE)),
    ("ransom_extension",
     re.compile(r"\.(wncry|wcry|locked|encrypted|crypt|cryzip|onion|paymt|"
                r"kcrypt|conti|lockbit|ryuk|kraken)\b",
                re.IGNORECASE)),
    ("anti_recovery_vssadmin",
     re.compile(r"vssadmin[\s\.]+delete\s+shadows", re.IGNORECASE)),
    ("anti_recovery_bcdedit",
     re.compile(r"bcdedit\b.*recoveryenabled\s+no", re.IGNORECASE)),
    ("anti_recovery_wbadmin",
     re.compile(r"wbadmin\s+delete\s+(catalog|systemstatebackup)",
                re.IGNORECASE)),
    ("shell_cmd",
     re.compile(r"^\s*cmd\.exe\s+/c\s+", re.IGNORECASE)),
    ("shell_powershell",
     re.compile(r"powershell(\.exe)?\s+-(ep|enc|executionpolicy|encodedcommand|"
                r"w\s+hidden)",
                re.IGNORECASE)),
    ("registry_run_key",
     re.compile(r"Software\\\\?Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run",
                re.IGNORECASE)),
    ("mutex_candidate",
     re.compile(r"^(Global\\|Local\\)[A-Za-z0-9_\-]{4,}$")),
]


# Sensitive API names that are frequently resolved dynamically and so
# may appear only as string literals, not in the static import table.
_SENSITIVE_API_CATEGORIES: dict[str, str] = {
    # --- Cryptographic primitives (ransomware signal) ---------------------
    "CryptEncrypt":            "sensitive_api_crypto",
    "CryptDecrypt":            "sensitive_api_crypto",
    "CryptGenKey":             "sensitive_api_crypto",
    "CryptImportKey":          "sensitive_api_crypto",
    "CryptExportKey":          "sensitive_api_crypto",
    "CryptHashData":           "sensitive_api_crypto",
    "CryptAcquireContextA":    "sensitive_api_crypto",
    "CryptAcquireContextW":    "sensitive_api_crypto",
    "CryptReleaseContext":     "sensitive_api_crypto",
    "CryptDestroyKey":         "sensitive_api_crypto",
    "BCryptEncrypt":           "sensitive_api_crypto",
    "BCryptDecrypt":           "sensitive_api_crypto",
    "BCryptGenerateSymmetricKey": "sensitive_api_crypto",
    # --- Process injection -------------------------------------------------
    "VirtualAllocEx":          "sensitive_api_injection",
    "WriteProcessMemory":      "sensitive_api_injection",
    "CreateRemoteThread":      "sensitive_api_injection",
    "NtMapViewOfSection":      "sensitive_api_injection",
    "NtUnmapViewOfSection":    "sensitive_api_injection",
    "SetThreadContext":        "sensitive_api_injection",
    "ResumeThread":            "sensitive_api_injection",
    # --- Surveillance ------------------------------------------------------
    "SetWindowsHookExA":       "sensitive_api_surveillance",
    "SetWindowsHookExW":       "sensitive_api_surveillance",
    "GetAsyncKeyState":        "sensitive_api_surveillance",
    "GetForegroundWindow":     "sensitive_api_surveillance",
    "BitBlt":                  "sensitive_api_surveillance",
    "GetDC":                   "sensitive_api_surveillance",
    "CreateCompatibleBitmap":  "sensitive_api_surveillance",
    # --- C2 / network ------------------------------------------------------
    "InternetOpenA":           "sensitive_api_c2",
    "InternetOpenW":           "sensitive_api_c2",
    "HttpSendRequestA":        "sensitive_api_c2",
    "HttpSendRequestW":        "sensitive_api_c2",
    "WinHttpOpenRequest":      "sensitive_api_c2",
    "WinHttpSendRequest":      "sensitive_api_c2",
    # --- Persistence -------------------------------------------------------
    "RegSetValueExA":          "sensitive_api_persistence",
    "RegSetValueExW":          "sensitive_api_persistence",
    "CreateServiceA":          "sensitive_api_persistence",
    "CreateServiceW":          "sensitive_api_persistence",
    # --- Credential theft --------------------------------------------------
    "CredEnumerateA":          "sensitive_api_credentials",
    "CryptUnprotectData":      "sensitive_api_credentials",
}


def classify_string(s: str) -> str | None:
    """Return the primary category label for *s*, or None for uncategorized.

    Sensitive API names are matched by exact equality (case-sensitive
    because Windows API names are mixed-case and classifying by
    case-insensitive match would generate false positives on common
    English strings such as ``Setup`` matching a ``Set*`` prefix).
    """
    if s in _SENSITIVE_API_CATEGORIES:
        return _SENSITIVE_API_CATEGORIES[s]
    trimmed = s.strip()
    for cat, pat in _CATEGORY_PATTERNS:
        if pat.search(trimmed):
            return cat
    return None


# ---------------------------------------------------------------------------
# Public tagging + indirect-API detection
# ---------------------------------------------------------------------------

def extract_tagged_strings(data: bytes,
                           existing_imports: set[str] | None = None,
                           *,
                           cap: int = TAGGED_STRING_CAP) -> list[dict[str, Any]]:
    """Extract and classify strings; mark sensitive API strings that
    are NOT in the static import table.

    Parameters
    ----------
    data : bytes
        Raw PE bytes.
    existing_imports : set[str] or None
        Set of function names already present in the static import
        table. Used to determine which sensitive-API strings indicate
        dynamic resolution.

    Returns
    -------
    list of dicts, each: {value, category, indirect_api (optional)}
    """
    existing = existing_imports or set()
    raw = extract_strings(data)
    tagged: list[dict[str, Any]] = []
    for s in raw:
        cat = classify_string(s)
        if cat is None:
            continue
        rec: dict[str, Any] = {"value": s, "category": cat}
        if cat.startswith("sensitive_api_"):
            rec["indirect_api"] = s not in existing
        tagged.append(rec)
        if len(tagged) >= cap:
            break
    return tagged


def detect_dynamic_api_resolution(
        tagged: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """From a tagged string list, return records for sensitive API names
    that are flagged as ``indirect_api=True``.

    Each returned record contains the API name, its category, and a
    short rationale that downstream reports and baseline rules can
    cite verbatim.
    """
    out: list[dict[str, Any]] = []
    for rec in tagged:
        if (rec.get("category", "").startswith("sensitive_api_")
                and rec.get("indirect_api")):
            out.append({
                "api_name": rec["value"],
                "category": rec["category"],
                "rationale": (
                    "API name present as string literal but NOT in the "
                    "static import table; consistent with dynamic "
                    "resolution via GetProcAddress."
                ),
            })
    return out

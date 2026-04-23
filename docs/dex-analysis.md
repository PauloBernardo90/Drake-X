# DEX Deep Analysis Pipeline

Drake-X's DEX analysis layer provides multi-DEX aware static analysis for
Android malware research. It extracts structured, evidence-based findings
from APK/DEX files using a combination of binary header parsing, smali
bytecode analysis, Java decompilation, and optional androguard integration.

## Pipeline Overview

```
APK File
  │
  ├─ Phase 1:  Unpack APK → enumerate DEX files
  ├─ Phase 2:  jadx decompilation → Java source corpus
  ├─ Phase 3:  apktool decompilation → smali corpus + manifest
  ├─ Phase 4:  androguard analysis (optional) → precise class/method inventory
  ├─ Phase 5:  String extraction + classification
  ├─ Phase 6:  Sensitive API detection
  ├─ Phase 7:  Obfuscation analysis
  ├─ Phase 8:  Packing / multi-DEX indicator detection
  ├─ Phase 9:  Call graph construction
  └─ Phase 10: Finding consolidation + report generation
```

Each phase is independent and produces structured output. If a tool is
unavailable (e.g., jadx not installed), the pipeline degrades gracefully
and continues with available data.

## Dependencies

### Required (Python)

- Python 3.11+
- pydantic >= 2.6.0
- All Drake-X core dependencies

### External Tools (optional but recommended)

| Tool | Purpose | Install |
|------|---------|---------|
| `jadx` | DEX → Java decompilation | `apt install jadx` or [GitHub](https://github.com/skylot/jadx) |
| `apktool` | DEX → smali + resources | `apt install apktool` or [GitHub](https://github.com/iBotPeaches/Apktool) |
| `androguard` | Precise DEX parsing in Python | `pip install androguard` |

The pipeline works without any external tools (using binary header parsing
only), but fidelity improves significantly with jadx + apktool.

## Usage

### As part of the APK pipeline

```python
from drake_x.dex import run_dex_analysis
from pathlib import Path

result = run_dex_analysis(
    apk_path=Path("sample.apk"),
    work_dir=Path("/tmp/dex_work"),
    use_jadx=True,
    use_apktool=True,
    use_androguard=True,
)

# Access structured results
print(f"DEX files: {len(result.dex_files)}")
print(f"Sensitive APIs: {len(result.sensitive_api_hits)}")
print(f"Obfuscation score: {result.obfuscation_score:.0%}")
print(f"Total findings: {len(result.findings)}")
```

### Generate reports

```python
from drake_x.dex.report import write_json_report, write_markdown_report

write_json_report(result, Path("output/dex_report.json"))
write_markdown_report(result, Path("output/dex_report.md"), apk_name="sample.apk")
```

### Individual analyzers

Each analyzer can be used independently:

```python
from drake_x.dex.sensitive_apis import detect_sensitive_apis
from drake_x.dex.strings import classify_strings
from drake_x.dex.obfuscation import analyze_obfuscation

# Detect APIs in any text corpus
hits = detect_sensitive_apis(java_source_text)

# Classify raw strings
classified = classify_strings(["https://evil.com/gate.php", "com.bank.app"])

# Analyze obfuscation
indicators, score = analyze_obfuscation(smali_text=smali_corpus)
```

## Output Format

### DexAnalysisResult

Top-level container with all analysis results:

```json
{
  "dex_files": [...],
  "total_classes": 160,
  "total_methods": 800,
  "sensitive_api_hits": [...],
  "classified_strings": [...],
  "obfuscation_indicators": [...],
  "obfuscation_score": 0.35,
  "packing_indicators": [...],
  "call_edges": [...],
  "findings": [...],
  "tools_used": ["jadx", "apktool"],
  "warnings": [],
  "analysis_phases_completed": [...]
}
```

### DexFinding (evidence model)

Every finding carries full provenance:

```json
{
  "finding_id": "f-a1b2c3d4e5",
  "source_tool": "sensitive_api_detector",
  "dex_origin": "classes2.dex",
  "file_origin": "",
  "evidence_type": "sensitive_api",
  "raw_snippet": "SmsManager.getDefault().sendTextMessage(...)",
  "normalized_interpretation": "sms: SmsManager detected",
  "confidence": 0.85,
  "severity": "high",
  "category": "sms",
  "tags": ["T1582.001"],
  "relation_links": [],
  "metadata": {}
}
```

### Severity levels

| Level | Meaning |
|-------|---------|
| `critical` | High-impact, high-confidence finding |
| `high` | Likely malicious or security-critical |
| `medium` | Suspicious, warrants investigation |
| `low` | Informational security signal |
| `info` | Neutral observation |

## Detectors

### Sensitive API Detector

Detects usage of 25+ Android APIs across 16 categories:

| Category | Examples | ATT&CK |
|----------|----------|--------|
| `accessibility_service` | AccessibilityService, performAction | T1517 |
| `package_installer` | PackageInstaller, ACTION_INSTALL_PACKAGE | T1398 |
| `webview` | WebView.loadUrl, addJavascriptInterface | T1185 |
| `sms` | SmsManager, content://sms | T1582.001 |
| `telephony` | TelephonyManager, getDeviceId | T1426 |
| `device_admin` | DevicePolicyManager, lockNow | T1401 |
| `runtime_exec` | Runtime.exec, ProcessBuilder | T1059.004 |
| `dex_loading` | DexClassLoader, InMemoryDexClassLoader | T1407 |
| `reflection` | Class.forName, Method.invoke | T1620 |
| `crypto` | Cipher.getInstance, AES/DES | — |
| `camera` | CameraManager, takePicture | T1512 |
| `location` | LocationManager, FusedLocationProvider | T1430 |
| `clipboard` | ClipboardManager, getPrimaryClip | T1414 |
| `contacts` | ContactsContract | T1636.003 |
| `network` | HttpURLConnection, OkHttp | — |
| `file_provider` | FileProvider, getUriForFile | — |

### String Classifier

Categorizes extracted strings into:

- **URL** — HTTP/HTTPS URLs (excluding common framework domains)
- **IP** — Public IPv4 addresses
- **Domain** — Domains with suspicious TLDs
- **C2 Indicator** — Patterns like `/gate.php`, `/panel/`, `/beacon`
- **Phishing** — Card numbers, CVV, bank login patterns
- **Encoded Blob** — Base64/hex strings ≥32 chars
- **Crypto** — AES, RSA, certificate references
- **Package Target** — Third-party package names (potential overlay targets)
- **Filesystem Path** — Android filesystem paths
- **Command** — Shell commands (su, chmod, pm, am)

### Obfuscation Analyzer

8 heuristic detectors with confidence scoring:

1. **Short identifiers** — Single-char class/method names (ProGuard/R8)
2. **Reflection abuse** — Heavy use of Class.forName, invoke
3. **Encoded strings** — High ratio of base64/hex blobs
4. **Multi-DEX splitting** — >2 DEX files as evasion signal
5. **Dynamic loading** — DexClassLoader, InMemoryDexClassLoader
6. **Identifier renaming** — Sequential single-letter names per package
7. **Control flow** — Excessive gotos and switch tables in smali
8. **Native bridge** — System.loadLibrary patterns

Produces an overall obfuscation score (0.0–1.0).

### Packing Indicator Detector

Flags:
- High DEX count (>3 files)
- Hidden DEX files (in assets/, res/, lib/)
- Non-standard DEX names
- Dropper pattern (small primary, large secondary)
- Unequal class distribution

## Interpreting Findings

### Confidence levels

- **≥ 0.8**: Strong signal — likely genuine
- **0.6–0.8**: Moderate signal — warrants review
- **0.4–0.6**: Weak signal — contextual
- **< 0.4**: Low signal — may be false positive

### Reading the obfuscation score

- **0.0–0.2**: Clean / minimal obfuscation (typical legitimate app)
- **0.2–0.4**: Light obfuscation (ProGuard/R8 defaults)
- **0.4–0.6**: Moderate obfuscation (custom configuration)
- **0.6–0.8**: Heavy obfuscation (likely intentional evasion)
- **0.8–1.0**: Extreme obfuscation (strong packing/protection)

### False positives

Common legitimate uses that may trigger detectors:

- **Accessibility**: Screen readers, testing frameworks
- **Crypto**: HTTPS certificate pinning, encrypted preferences
- **Reflection**: Dependency injection (Dagger/Hilt), serialization
- **WebView**: In-app browsers, hybrid apps
- **Multi-DEX**: Apps exceeding the 65K method limit

Always correlate multiple signals before drawing conclusions.

## Limitations

1. **Static analysis only** — Cannot resolve runtime-generated values,
   encrypted payloads, or server-side logic.
2. **Call graph approximation** — Smali-based call graph does not handle
   virtual dispatch, interface polymorphism, or reflection targets.
3. **No symbolic execution** — Cannot determine reachability or trigger
   conditions for suspicious code paths.
4. **Tool dependency** — Accuracy improves with jadx + apktool + androguard.
   Without these tools, only binary header parsing is available.
5. **No dynamic DEX loading resolution** — If the APK downloads or decrypts
   additional DEX files at runtime, they won't be analyzed.
6. **String extraction fidelity** — Direct binary parsing may miss some
   strings; androguard provides better coverage.

## Module Architecture

```
drake_x/dex/
├── __init__.py            # Package entry point
├── pipeline.py            # 10-phase orchestrator
├── parser.py              # DEX binary header parsing
├── multidex.py            # Multi-DEX enumeration and correlation
├── smali_analyzer.py      # Smali bytecode structural analysis
├── sensitive_apis.py      # Sensitive API pattern detection
├── strings.py             # String classification engine
├── obfuscation.py         # Obfuscation heuristic analysis
├── callgraph.py           # Call graph / relation graph builder
├── jadx_bridge.py         # jadx integration
├── apktool_bridge.py      # apktool integration
├── androguard_bridge.py   # androguard integration (optional)
└── report.py              # Report generation (JSON + Markdown)

drake_x/models/dex.py       # Pydantic data models
```

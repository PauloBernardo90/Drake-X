"""Obfuscation analysis for DEX content.

Implements heuristic detectors for:

- Short/meaningless identifier names (ProGuard/R8 artifacts)
- Reflection abuse patterns
- High ratio of encoded/encrypted strings
- Multi-DEX splitting as evasion
- Dynamic loading patterns
- Suspicious identifier renaming
- Control-flow obfuscation indicators
- Native bridge patterns

Each detector produces :class:`ObfuscationIndicator` findings with
explicit evidence and confidence.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..logging import get_logger
from ..models.dex import (
    DexClassInfo,
    DexFileInfo,
    DexFindingSeverity,
    DexMethodInfo,
    ObfuscationIndicator,
    ObfuscationSignal,
)

log = get_logger("dex.obfuscation")


def analyze_obfuscation(
    *,
    classes: list[DexClassInfo] | None = None,
    methods: list[DexMethodInfo] | None = None,
    dex_infos: list[DexFileInfo] | None = None,
    raw_strings: list[str] | None = None,
    smali_text: str = "",
    java_text: str = "",
) -> tuple[list[ObfuscationIndicator], float]:
    """Run all obfuscation heuristics and return indicators + overall score.

    The score is 0.0 (no obfuscation signals) to 1.0 (heavy obfuscation).
    """
    indicators: list[ObfuscationIndicator] = []

    indicators.extend(_check_short_identifiers(classes, methods))
    indicators.extend(_check_reflection_abuse(smali_text or java_text))
    indicators.extend(_check_encoded_strings(raw_strings or []))
    indicators.extend(_check_multi_dex_splitting(dex_infos or []))
    indicators.extend(_check_dynamic_loading(smali_text or java_text))
    indicators.extend(_check_identifier_renaming(classes))
    indicators.extend(_check_control_flow(smali_text))
    indicators.extend(_check_native_bridge(smali_text or java_text, classes))

    score = _compute_score(indicators)
    log.info("Obfuscation analysis: %d indicators, score=%.2f", len(indicators), score)

    return indicators, score


def _check_short_identifiers(
    classes: list[DexClassInfo] | None,
    methods: list[DexMethodInfo] | None,
) -> list[ObfuscationIndicator]:
    """Detect single-char or very short class/method names."""
    if not classes and not methods:
        return []

    short_classes = 0
    short_methods = 0
    total_classes = 0
    total_methods = 0

    if classes:
        for cls in classes:
            total_classes += 1
            short = cls.class_name.rsplit(".", 1)[-1]
            if len(short) <= 2 and short.isalpha():
                short_classes += 1

    if methods:
        for m in methods:
            if m.is_constructor:
                continue
            total_methods += 1
            if len(m.method_name) <= 2 and m.method_name.isalpha():
                short_methods += 1

    indicators: list[ObfuscationIndicator] = []

    if short_classes > 10:
        ratio = short_classes / max(total_classes, 1)
        conf = min(0.9, 0.3 + ratio)
        indicators.append(ObfuscationIndicator(
            signal=ObfuscationSignal.SHORT_IDENTIFIERS,
            description=f"{short_classes}/{total_classes} classes have <=2 char names",
            evidence=[f"Short class count: {short_classes}", f"Ratio: {ratio:.2%}"],
            confidence=conf,
            severity=DexFindingSeverity.MEDIUM if ratio > 0.3 else DexFindingSeverity.LOW,
        ))

    if short_methods > 20:
        ratio = short_methods / max(total_methods, 1)
        conf = min(0.9, 0.3 + ratio)
        indicators.append(ObfuscationIndicator(
            signal=ObfuscationSignal.SHORT_IDENTIFIERS,
            description=f"{short_methods}/{total_methods} methods have <=2 char names",
            evidence=[f"Short method count: {short_methods}", f"Ratio: {ratio:.2%}"],
            confidence=conf,
            severity=DexFindingSeverity.MEDIUM if ratio > 0.3 else DexFindingSeverity.LOW,
        ))

    return indicators


def _check_reflection_abuse(text: str) -> list[ObfuscationIndicator]:
    """Detect heavy use of Java reflection APIs."""
    if not text:
        return []

    patterns = {
        "Class.forName": re.findall(r"Class\.forName\(", text),
        "Method.invoke": re.findall(r"\.invoke\(", text),
        "getDeclaredMethod": re.findall(r"getDeclaredMethod|getDeclaredField", text),
        "getMethod": re.findall(r"getMethod\(|getField\(", text),
    }

    total = sum(len(v) for v in patterns.values())
    if total < 5:
        return []

    evidence = [f"{k}: {len(v)} occurrences" for k, v in patterns.items() if v]
    confidence = min(0.9, 0.4 + total * 0.02)

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.REFLECTION_ABUSE,
        description=f"{total} reflection API calls detected",
        evidence=evidence,
        confidence=confidence,
        severity=DexFindingSeverity.HIGH if total > 20 else DexFindingSeverity.MEDIUM,
    )]


def _check_encoded_strings(raw_strings: list[str]) -> list[ObfuscationIndicator]:
    """Detect high ratio of base64/hex encoded strings."""
    if not raw_strings:
        return []

    b64_re = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
    hex_re = re.compile(r"^[0-9a-fA-F]{20,}$")

    encoded_count = sum(
        1 for s in raw_strings
        if b64_re.match(s.strip()) or hex_re.match(s.strip())
    )

    if encoded_count < 5:
        return []

    ratio = encoded_count / max(len(raw_strings), 1)
    confidence = min(0.85, 0.3 + ratio * 2)

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.ENCODED_STRINGS,
        description=f"{encoded_count}/{len(raw_strings)} strings appear encoded",
        evidence=[f"Encoded string count: {encoded_count}", f"Ratio: {ratio:.2%}"],
        confidence=confidence,
        severity=DexFindingSeverity.MEDIUM,
    )]


def _check_multi_dex_splitting(
    dex_infos: list[DexFileInfo],
) -> list[ObfuscationIndicator]:
    """Flag multi-DEX as potential obfuscation vector."""
    if len(dex_infos) <= 2:
        return []

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.MULTI_DEX_SPLITTING,
        description=f"APK contains {len(dex_infos)} DEX files",
        evidence=[f"{d.filename}: {d.class_count} classes" for d in dex_infos],
        confidence=0.4 + min(0.4, len(dex_infos) * 0.05),
        severity=DexFindingSeverity.LOW,
        affected_dex=[d.filename for d in dex_infos],
    )]


def _check_dynamic_loading(text: str) -> list[ObfuscationIndicator]:
    """Detect dynamic class/DEX loading patterns."""
    if not text:
        return []

    loaders = {
        "DexClassLoader": len(re.findall(r"DexClassLoader", text)),
        "InMemoryDexClassLoader": len(re.findall(r"InMemoryDexClassLoader", text)),
        "PathClassLoader": len(re.findall(r"PathClassLoader", text)),
        "DexFile": len(re.findall(r"dalvik[./]system[./]DexFile", text)),
        "loadClass": len(re.findall(r"\.loadClass\(", text)),
    }

    total = sum(loaders.values())
    if total == 0:
        return []

    evidence = [f"{k}: {v}" for k, v in loaders.items() if v > 0]
    confidence = min(0.9, 0.5 + total * 0.05)

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.DYNAMIC_LOADING,
        description=f"{total} dynamic class loading pattern(s) detected",
        evidence=evidence,
        confidence=confidence,
        severity=DexFindingSeverity.HIGH if total > 3 else DexFindingSeverity.MEDIUM,
    )]


def _check_identifier_renaming(
    classes: list[DexClassInfo] | None,
) -> list[ObfuscationIndicator]:
    """Detect systematic identifier renaming (sequential single-char names)."""
    if not classes:
        return []

    # Look for sequential single-letter class names in the same package
    pkg_names: dict[str, list[str]] = {}
    for cls in classes:
        short = cls.class_name.rsplit(".", 1)[-1]
        if len(short) == 1 and short.isalpha():
            pkg_names.setdefault(cls.package, []).append(short)

    suspicious_pkgs = [
        (pkg, sorted(names))
        for pkg, names in pkg_names.items()
        if len(names) >= 5
    ]

    if not suspicious_pkgs:
        return []

    evidence = [
        f"{pkg}: {', '.join(names[:10])} ({len(names)} classes)"
        for pkg, names in suspicious_pkgs
    ]

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.IDENTIFIER_RENAMING,
        description=f"Systematic identifier renaming in {len(suspicious_pkgs)} package(s)",
        evidence=evidence,
        confidence=0.8,
        severity=DexFindingSeverity.MEDIUM,
    )]


def _check_control_flow(smali_text: str) -> list[ObfuscationIndicator]:
    """Detect control-flow obfuscation in smali (excessive gotos, switch tables)."""
    if not smali_text:
        return []

    goto_count = len(re.findall(r"\bgoto\b", smali_text))
    switch_count = len(re.findall(r"packed-switch|sparse-switch", smali_text))

    # These are heuristic — legitimate code has gotos too, but very high
    # density suggests obfuscation
    if goto_count < 500 and switch_count < 100:
        return []

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.CONTROL_FLOW,
        description=f"High control-flow complexity: {goto_count} gotos, {switch_count} switch tables",
        evidence=[f"goto count: {goto_count}", f"switch count: {switch_count}"],
        confidence=0.5,
        severity=DexFindingSeverity.LOW,
    )]


def _check_native_bridge(
    text: str,
    classes: list[DexClassInfo] | None,
) -> list[ObfuscationIndicator]:
    """Detect native method bridges that may hide functionality."""
    if not text:
        return []

    native_calls = len(re.findall(r"System\.loadLibrary|System\.load\(", text))
    jni_methods = 0
    if classes:
        # Count classes with high native method ratios (would need methods too)
        pass

    if native_calls < 2:
        return []

    return [ObfuscationIndicator(
        signal=ObfuscationSignal.NATIVE_BRIDGE,
        description=f"{native_calls} native library load(s) detected",
        evidence=[f"System.loadLibrary/load calls: {native_calls}"],
        confidence=0.5,
        severity=DexFindingSeverity.LOW,
    )]


def _compute_score(indicators: list[ObfuscationIndicator]) -> float:
    """Compute aggregate obfuscation score from individual indicators."""
    if not indicators:
        return 0.0

    # Weighted sum of indicator confidences
    weights = {
        ObfuscationSignal.SHORT_IDENTIFIERS: 0.15,
        ObfuscationSignal.REFLECTION_ABUSE: 0.2,
        ObfuscationSignal.ENCODED_STRINGS: 0.15,
        ObfuscationSignal.MULTI_DEX_SPLITTING: 0.05,
        ObfuscationSignal.DYNAMIC_LOADING: 0.2,
        ObfuscationSignal.IDENTIFIER_RENAMING: 0.1,
        ObfuscationSignal.CONTROL_FLOW: 0.1,
        ObfuscationSignal.NATIVE_BRIDGE: 0.05,
    }

    score = 0.0
    for ind in indicators:
        w = weights.get(ind.signal, 0.1)
        score += w * ind.confidence

    return min(1.0, score)

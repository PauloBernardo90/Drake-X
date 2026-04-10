"""Obfuscation and packing assessment for APK samples.

Evaluates evidence from multiple sources (file listing, strings, smali,
native libs, assets) and produces :class:`ObfuscationTrait` rows with
explicit confidence and supporting evidence.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ...models.apk import ObfuscationConfidence, ObfuscationTrait


def assess_obfuscation(
    *,
    file_listing: list[str] | None = None,
    smali_text: str = "",
    strings_text: str = "",
    asset_names: list[str] | None = None,
    native_lib_names: list[str] | None = None,
) -> list[ObfuscationTrait]:
    """Run all obfuscation heuristics and return the combined traits."""
    traits: list[ObfuscationTrait] = []

    traits.extend(_check_identifier_renaming(smali_text))
    traits.extend(_check_string_encryption(strings_text, smali_text))
    traits.extend(_check_high_entropy_assets(asset_names or []))
    traits.extend(_check_packer_signatures(file_listing or [], smali_text))
    traits.extend(_check_native_indirection(native_lib_names or [], smali_text))
    traits.extend(_check_reflection_abuse(smali_text))

    return traits


def _check_identifier_renaming(smali: str) -> list[ObfuscationTrait]:
    """Look for single-character class/method names typical of ProGuard/R8."""
    if not smali:
        return []
    short_names = re.findall(r'\.method\s+.*\s([a-z])\(', smali)
    short_classes = re.findall(r'\.class\s+.*L[a-z0-9]+/[a-z];', smali)
    count = len(short_names) + len(short_classes)
    if count > 20:
        return [ObfuscationTrait(
            trait="identifier_renaming",
            confidence=ObfuscationConfidence.HIGH,
            evidence=[f"{count} single-char method/class names in smali"],
            notes="Consistent with ProGuard / R8 or similar minifier.",
        )]
    if count > 5:
        return [ObfuscationTrait(
            trait="identifier_renaming",
            confidence=ObfuscationConfidence.MEDIUM,
            evidence=[f"{count} short identifiers in smali"],
        )]
    return []


def _check_string_encryption(strings_text: str, smali: str) -> list[ObfuscationTrait]:
    """Detect signs of string encryption (base64 blobs, decrypt methods)."""
    traits: list[ObfuscationTrait] = []
    b64_blobs = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', strings_text)
    if len(b64_blobs) > 10:
        traits.append(ObfuscationTrait(
            trait="string_encryption_or_encoding",
            confidence=ObfuscationConfidence.MEDIUM,
            evidence=[f"{len(b64_blobs)} base64-like blobs in strings output"],
        ))
    if re.search(r'decrypt|Cipher\.getInstance|AES|DES|javax\.crypto', smali, re.I):
        traits.append(ObfuscationTrait(
            trait="crypto_string_decryption",
            confidence=ObfuscationConfidence.MEDIUM,
            evidence=["Crypto API references found in smali (Cipher, AES, DES)"],
        ))
    return traits


def _check_high_entropy_assets(asset_names: list[str]) -> list[ObfuscationTrait]:
    """Flag assets with suspicious extensions or names that look encrypted."""
    suspicious = [
        n for n in asset_names
        if re.search(r'\.(bin|dat|enc|crypt|blob|raw|pack|zip)$', n, re.I)
        or re.match(r'^[a-f0-9]{16,}', n.split("/")[-1])
    ]
    if suspicious:
        return [ObfuscationTrait(
            trait="encrypted_or_packed_assets",
            confidence=ObfuscationConfidence.MEDIUM,
            evidence=[f"Suspicious asset names: {', '.join(suspicious[:5])}"],
        )]
    return []


def _check_packer_signatures(file_listing: list[str], smali: str) -> list[ObfuscationTrait]:
    """Detect well-known packer / protector artifacts."""
    traits: list[ObfuscationTrait] = []
    listing_lower = "\n".join(file_listing).lower()

    packer_sigs = [
        ("jiagu", "360 Jiagu / Qihoo packer"),
        ("libjiagu", "360 Jiagu native library"),
        ("libsecexe", "Bangcle / SecNeo packer"),
        ("libDexHelper", "Tencent Legu packer"),
        ("libtosprotection", "Tencent protection"),
        ("libexec", "iJiami packer"),
        ("assets/classes.dex.dat", "Packed secondary DEX"),
    ]
    for sig, label in packer_sigs:
        if sig.lower() in listing_lower:
            traits.append(ObfuscationTrait(
                trait="known_packer",
                confidence=ObfuscationConfidence.HIGH,
                evidence=[f"Packer signature: {label} (matched '{sig}')"],
                notes=label,
            ))

    # Multi-dex with suspiciously named secondary DEX files
    extra_dex = [f for f in file_listing if re.search(r'classes\d+\.dex', f)]
    if len(extra_dex) > 3:
        traits.append(ObfuscationTrait(
            trait="multi_dex_packing",
            confidence=ObfuscationConfidence.LOW,
            evidence=[f"{len(extra_dex)} DEX files found (may indicate packing or large app)"],
        ))

    return traits


def _check_native_indirection(lib_names: list[str], smali: str) -> list[ObfuscationTrait]:
    """Detect native-layer indirection (JNI entry point for logic)."""
    if not lib_names:
        return []
    native_calls = len(re.findall(r'\.method.*native\b', smali))
    if native_calls > 10:
        return [ObfuscationTrait(
            trait="native_indirection",
            confidence=ObfuscationConfidence.MEDIUM,
            evidence=[
                f"{native_calls} native method declarations in smali",
                f"Native libs: {', '.join(lib_names[:5])}",
            ],
        )]
    return []


def _check_reflection_abuse(smali: str) -> list[ObfuscationTrait]:
    """Count reflection-heavy patterns."""
    if not smali:
        return []
    reflection_calls = len(re.findall(
        r'invoke-virtual.*Method->invoke|Class->forName|getMethod|getDeclaredMethod',
        smali,
    ))
    if reflection_calls > 15:
        return [ObfuscationTrait(
            trait="reflection_abuse",
            confidence=ObfuscationConfidence.HIGH,
            evidence=[f"{reflection_calls} reflection invocations in smali"],
        )]
    if reflection_calls > 5:
        return [ObfuscationTrait(
            trait="reflection_abuse",
            confidence=ObfuscationConfidence.MEDIUM,
            evidence=[f"{reflection_calls} reflection invocations in smali"],
        )]
    return []

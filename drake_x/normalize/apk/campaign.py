"""Campaign similarity assessor.

Maps observed TTP-style traits from the analysis result to generic
mobile-malware tradecraft categories. Uses conservative language:

- ``consistent_with`` — multiple strong indicators match
- ``shares_traits`` — some indicators match, some don't
- ``tentatively_resembles`` — weak signals
- ``insufficient_evidence`` — nothing conclusive

Does NOT claim attribution to a specific threat actor or malware family.
"""

from __future__ import annotations

from ...models.apk import (
    ApkAnalysisResult,
    BehaviorIndicator,
    CampaignAssessment,
    CampaignSimilarity,
)


def assess_campaigns(result: ApkAnalysisResult) -> list[CampaignAssessment]:
    """Evaluate the analysis result against known campaign categories."""
    assessments: list[CampaignAssessment] = []
    cats = set(b.category for b in result.behavior_indicators)
    patterns = set(b.pattern for b in result.behavior_indicators)
    perm_names = set(p.name for p in result.permissions)

    assessments.append(_assess_dropper(cats, patterns, perm_names))
    assessments.append(_assess_banker(cats, patterns, perm_names))
    assessments.append(_assess_spyware(cats, patterns, perm_names))
    assessments.append(_assess_loader(cats, patterns, perm_names))
    assessments.append(_assess_fake_update(cats, patterns, perm_names))
    assessments.append(_assess_fcm_abuser(cats, patterns, perm_names))

    return assessments


def _assess_dropper(cats, patterns, perms) -> CampaignAssessment:
    traits = []
    if "dropper" in cats:
        traits.append("dropper behavior patterns")
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        traits.append("REQUEST_INSTALL_PACKAGES permission")
    if "dynamic_loading" in cats:
        traits.append("dynamic code loading")
    return _make("dropper", traits)


def _assess_banker(cats, patterns, perms) -> CampaignAssessment:
    traits = []
    if any("AccessibilityService" in p for p in patterns):
        traits.append("AccessibilityService abuse")
    if any("overlay" in str(p).lower() for p in patterns):
        traits.append("overlay / phishing patterns")
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
        traits.append("BIND_ACCESSIBILITY_SERVICE permission")
    if any("banking" in p.lower() or "credential" in p.lower() for p in patterns):
        traits.append("banking/credential phishing strings")
    if "android.permission.READ_SMS" in perms or "android.permission.RECEIVE_SMS" in perms:
        traits.append("SMS interception permissions")
    return _make("banker-like", traits)


def _assess_spyware(cats, patterns, perms) -> CampaignAssessment:
    traits = []
    spy_perms = {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
    }
    matched = spy_perms & perms
    if len(matched) >= 3:
        traits.append(f"{len(matched)} surveillance-class permissions")
    if "exfiltration" in cats:
        traits.append("exfiltration behavior indicators")
    if "persistence" in cats:
        traits.append("persistence mechanisms")
    return _make("spyware-like", traits)


def _assess_loader(cats, patterns, perms) -> CampaignAssessment:
    traits = []
    if "dynamic_loading" in cats:
        traits.append("dynamic code loading")
    if any("DexClassLoader" in p or "InMemoryDexClassLoader" in p for p in patterns):
        traits.append("DexClassLoader usage")
    if any(t.trait == "encrypted_or_packed_assets" for t in []):
        traits.append("encrypted assets")
    return _make("loader", traits)


def _assess_fake_update(cats, patterns, perms) -> CampaignAssessment:
    traits = []
    if "social_engineering" in cats:
        traits.append("social-engineering strings")
    if any("fake update" in p.lower() for p in patterns):
        traits.append("fake update string match")
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        traits.append("sideload capability")
    return _make("fake_update_lure", traits)


def _assess_fcm_abuser(cats, patterns, perms) -> CampaignAssessment:
    traits = []
    if any("Firebase" in p or "FCM" in p for p in patterns):
        traits.append("Firebase/FCM references")
    if "trigger_logic" in cats:
        traits.append("trigger/command logic patterns")
    return _make("fcm_abusing_malware", traits)


def _make(category: str, traits: list[str]) -> CampaignAssessment:
    if len(traits) >= 3:
        similarity = CampaignSimilarity.CONSISTENT_WITH
        confidence = min(0.8, 0.3 * len(traits))
    elif len(traits) == 2:
        similarity = CampaignSimilarity.SHARES_TRAITS
        confidence = 0.4
    elif len(traits) == 1:
        similarity = CampaignSimilarity.TENTATIVELY_RESEMBLES
        confidence = 0.2
    else:
        similarity = CampaignSimilarity.INSUFFICIENT_EVIDENCE
        confidence = 0.0

    return CampaignAssessment(
        category=category,
        similarity=similarity,
        matching_traits=traits,
        confidence=confidence,
    )

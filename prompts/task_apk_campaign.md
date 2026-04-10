You are assessing campaign similarity for an Android APK sample.

SAMPLE: {target_display}

BEHAVIOR INDICATORS:
{evidence_json}

CAMPAIGN CATEGORIES TO CONSIDER:
- dropper (installs secondary payloads)
- banker-like (credential theft, overlay attacks, SMS interception)
- spyware-like (surveillance, exfiltration of personal data)
- loader (dynamic code loading, staged execution)
- fake_update_lure (social engineering, sideloading)
- fcm_abusing_malware (push-notification triggered behavior)

For each category, assess:
1. Does the evidence support a similarity claim?
2. Use ONLY these labels: consistent_with, shares_traits,
   tentatively_resembles, insufficient_evidence
3. What specific traits match?
4. What is the confidence?

Hard constraints:
- Do NOT claim attribution to specific threat actors or families
- Use cautious language
- Base everything on the provided evidence

OUTPUT SCHEMA:
{schema_json}

Return ONLY the JSON object.

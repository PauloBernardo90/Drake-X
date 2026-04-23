You are analyzing the DEX bytecode of an Android APK sample. Below is
structured evidence from deep static analysis including sensitive API
detection, string classification, obfuscation assessment, multi-DEX
inventory, and call graph data.

SAMPLE: {target_display}

EVIDENCE:
{evidence_json}

FINDINGS:
{findings_json}

Based ONLY on the evidence provided, produce a structured threat
assessment covering:

1. **Threat summary**: What does this sample appear to do? Tie the
   individual signals into a coherent picture.
2. **Likely malware family**: If the evidence strongly suggests a known
   family (banker, dropper, spyware, ransomware, adware, etc.), name it.
   If insufficient evidence, return null.
3. **Key behaviors**: List the most significant behaviors with supporting
   evidence and severity.
4. **Obfuscation assessment**: How heavily is the sample obfuscated, and
   what techniques are used?
5. **Evasion techniques**: What evasion or anti-analysis methods are
   present?
6. **Target profile**: Who or what does the sample target (banking apps,
   specific regions, all users, etc.)?
7. **Confidence**: Overall confidence in the assessment.
8. **Pending confirmation**: What needs dynamic analysis to confirm?

Hard constraints:
- Only reference evidence that is in the input
- Clearly separate observed evidence from analytic assessment
- Do not claim attribution to specific threat actors or campaigns
- Do not suggest exploitation steps or offensive actions
- If evidence is thin, say so and lower confidence

OUTPUT SCHEMA:
{schema_json}

Return ONLY the JSON object.

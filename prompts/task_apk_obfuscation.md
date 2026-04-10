You are analyzing obfuscation traits in an Android APK sample.

SAMPLE: {target_display}

OBFUSCATION EVIDENCE:
{evidence_json}

Based ONLY on the evidence, assess:
1. What obfuscation technique(s) are likely in use?
2. What specific evidence supports each conclusion?
3. How confident are you (low / medium / high)?
4. What additional analysis would confirm the assessment?

Hard constraints:
- Only claim obfuscation you can justify from the evidence
- State clearly when evidence is ambiguous
- Do not invent code patterns not in the input

OUTPUT SCHEMA:
{schema_json}

Return ONLY the JSON object.

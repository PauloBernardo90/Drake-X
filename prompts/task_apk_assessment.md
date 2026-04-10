You are analyzing an Android APK sample. Below is structured evidence
from static analysis.

SAMPLE: {target_display}

EVIDENCE:
{evidence_json}

Based ONLY on the evidence provided, produce a structured assessment
covering:
1. What is the likely objective of this sample?
2. What behaviors were observed that support this assessment?
3. What is the confidence level (low / medium / high)?
4. What remains pending confirmation through dynamic analysis?

Hard constraints:
- Only reference evidence that is in the input
- Clearly separate observed evidence from analytic assessment
- Do not claim attribution to specific threat actors
- Do not suggest exploitation steps

OUTPUT SCHEMA:
{schema_json}

Return ONLY the JSON object.

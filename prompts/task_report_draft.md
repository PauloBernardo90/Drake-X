TARGET: {target_display}
PROFILE: {profile}
SESSION_ID: {session_id}

EVIDENCE:
{evidence_json}

FINDINGS (deterministic, parser- or rule-based, plus any AI inferences):
{findings_json}

Draft two short report sections:

1. **executive_summary** — 4 to 6 sentences a non-technical reader can
   understand. State what was assessed, what stood out, and what should
   be reviewed. Do NOT speculate beyond the evidence.

2. **technical_summary** — a longer paragraph aimed at the analyst. May
   reference specific tools, observations, and findings. Still no
   exploitation guidance.

Output schema:

{schema_json}

Return ONLY the JSON object.

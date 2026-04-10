TARGET: {target_display}

OBSERVATIONS TO CLASSIFY:
{observations_json}

For each observation, decide:
- severity: one of info, low, medium, high, critical (lean low if unsure)
- confidence: low, medium, high
- candidate CWE IDs (e.g. ["CWE-200"]), candidate OWASP categories
  (e.g. ["A05:2021"]), candidate MITRE ATT&CK technique IDs (e.g.
  ["T1595.001"]) — only include identifiers that are clearly justified by
  the evidence; otherwise leave the list empty.
- a one-sentence rationale that points back at the evidence.

Output a single JSON object:

{schema_json}

Do not invent observations that were not in the input. Do not propose
exploitation steps.

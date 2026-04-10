TARGET: {target_display}
PROFILE: {profile}

EVIDENCE:
{evidence_json}

Suggest the next SAFE recon steps a human analyst should consider. Each
step must be:

- non-destructive
- non-intrusive
- consistent with passive or light-active recon
- justified by something already in the evidence

Forbidden examples (do not propose any of these): exploitation, brute
force, fuzzing for vulnerabilities, payload generation, credential
testing, anything that aims at compromise rather than visibility.

Output schema:

{schema_json}

Return ONLY the JSON object.

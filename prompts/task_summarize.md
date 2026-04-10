TARGET: {target_display}
PROFILE: {profile}

EVIDENCE (parsed artifacts from local recon tools):
{evidence_json}

Produce a concise triage focused on what a human analyst should look at
next. Stay strictly within the evidence and respect every system-prompt
constraint.

OUTPUT SCHEMA (return one JSON object exactly matching these keys):
{schema_json}

Reminder: defensive recon only. No exploitation suggestions.
Return ONLY the JSON object.

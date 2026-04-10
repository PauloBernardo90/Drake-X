# Drake-X examples

This directory contains reference workspace artifacts.

- `workspace.toml` — example workspace configuration written by
  `drake init`. Edit `[ai].ollama_model` and `[engine].default_timeout` to
  match your setup.
- `scope.yaml` — example engagement scope file. Tighten this BEFORE running
  any active recon.

## Quick start

```bash
# 1. Scaffold a workspace
drake init my-engagement

# 2. Edit the scope file the init step wrote.
# It lives at ~/.drake-x/workspaces/my-engagement/scope.yaml.
$EDITOR ~/.drake-x/workspaces/my-engagement/scope.yaml

# 3. Validate
drake scope validate -w my-engagement
drake scope show     -w my-engagement

# 4. Confirm a target is in scope
drake scope check example.com -w my-engagement

# 5. Plan a passive recon run (no execution)
drake recon plan example.com -m recon_passive -w my-engagement

# 6. Run it for real
drake recon run example.com -m recon_passive -w my-engagement

# 7. List sessions and generate reports
drake report list -w my-engagement
drake report generate <session-id> -f executive -w my-engagement
drake report generate <session-id> -f json      -w my-engagement
drake report generate <session-id> -f manifest  -w my-engagement
```

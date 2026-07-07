# From janitor to gate: enforced controls

GrantGuard is a **detector and cleaner** — heuristics over your *user* allowlist.
It relies on you running it. It cannot stop an agent in the moment.

For controls that hold even against a misbehaving or jailbroken agent, the
enforcement has to live **above** the user, in an org-managed settings file that
users can't override.

## 1. Managed settings (enforced, not user-editable)

Deploy via MDM / config management to the per-OS path:

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\ProgramData\ClaudeCode\managed-settings.json` |

```jsonc
{
  "permissions": {
    "deny": [
      "Bash(security find-generic-password:*)",
      "Bash(secret-tool:*)",
      "Bash(git push:*)",
      "Bash(rm -rf:*)",
      "WebFetch"
    ]
  }
}
```

`deny` always wins over any user `allow` — so the holes GrantGuard cleans up
can't be re-added by a user clicking "always allow."

## 2. PreToolUse hook (deterministic policy gate)

A hook is a command the harness runs *before* a tool executes; a non-zero exit
**blocks** the call regardless of what the model decided.

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "python3 /opt/claude/guard.py" }]
      }
    ]
  }
}
```

`guard.py` reads the proposed command on stdin and exits non-zero if it contains
a credential pattern, a keychain read, or an exfil target — the exact classes
GrantGuard flags, but enforced instead of merely reported.

## 3. GrantGuard's role in this stack

- **Pre-deploy:** run it across the fleet to discover what risky permissions
  people have actually granted themselves — that data shapes your `deny` list.
- **Ongoing:** run it in CI/cron (`grantguard audit` exits non-zero on findings) as
  a drift detector for user-level settings.
- **Enforcement** is the managed `deny` + hooks above. Detector + gate together.

<p align="center">
  <img src="assets/banner.svg" alt="GrantGuard" width="100%" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Windows-2b3137?style=flat-square" alt="platform: macOS, Linux, Windows" />
  <img src="https://img.shields.io/badge/python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white" alt="python 3.10+" />
  <img src="https://img.shields.io/badge/dependencies-zero-34c759?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/built%20for-Claude%20Code-d97757?style=flat-square" alt="built for Claude Code" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT license" />
</p>

# GrantGuard

Audit, review, and clean up your Claude Code standing permissions.

GrantGuard audits the permission allowlist that Claude Code builds up as you click "always allow."
Hidden away in settings files that are rarely audited, these permissions strings can contain
substantive risks: API keys once pasted into a command, unrestricted `git push`, commands that read
your OS credential store, common destructive commands, and more.

GrantGuard classifies and groups granted permissions into risk groups, with a UI for easy review
and one-click removal of unsafe or unwanted permission grants.

GrantGuard runs as a small local Python app using Python's standard library and browser-native HTML/CSS/JS.
GrantGuard does not install or load third-party runtime Python packages, npm packages, web UI frameworks,
or CDN-hosted scripts.

### Highlights

- **Cross-platform.** Works on macOS, Linux, and Windows.
- **No third-party runtime packages.** Uses Python 3.10+ standard library code and browser-native HTML/CSS/JS.
  No `pip install`, no `npm install`, no build steps, and no CDN-loaded browser libraries.
- **Runs locally.** The web UI binds to `127.0.0.1` and makes no network calls. Your
  settings never leave the machine, and secrets are redacted in outputs.
- **Safe by default.** Auditing is read-only. Removals happen only when you confirm them,
  and they're non-destructive — Claude re-asks for anything removed, so you can re-approve it.


## Getting Started

### Requirements

- [`uv`](https://docs.astral.sh/uv) - a Python package and project manager, a modern best-in-class standard for python projects. GrantGuard uses `uv run` as its supported launch path, allowing consistent and convenient execution across MacOS, Linux, and Windows. 
- `git` - for cloning this repo
- A supported browser for the Web UI

GrantGuard uses browser-native HTML/CSS/JS and is intended for current stable
versions of Chrome, Edge, Firefox, and Safari.

### Quickstart

0. If you haven't already, [install `uv`](https://github.com/astral-sh/uv#installation).

1. Clone this repo
   ```bash
   git clone https://github.com/VantaInc/grantguard.git
   ```

2. Run the web UI
   ```bash
   cd grantguard
   uv run grantguard.py
   ```

By default, GrantGuard reviews user-level Claude settings sources only. It does
not infer a project from the directory where you launch it, and it does not walk
project directories unless you ask it to.

## CLI Usage

### Synopsis

```bash
uv run grantguard.py ui [TARGET ...] [--targets PATH] [--scan | --deep-scan] [--tolerance default|permissive] [--port PORT] [--no-open]
uv run grantguard.py audit [TARGET ...] [--targets PATH] [--scan | --deep-scan] [--tolerance default|permissive] [--show-safe] [--fix]
```

### Defaults

With no targets and no scan flag, GrantGuard inspects:

- `~/.claude/settings.json`
- `~/.claude/settings.local.json`
- `~/.claude.json`
- the platform managed settings file, if present

An empty selection is a successful empty audit. GrantGuard prints that no Claude
settings sources were found and exits `0`.

```bash
uv run grantguard.py audit
```

### Targets And Scans

Targets may be passed positionally or with repeatable `--targets PATH`; both
forms behave identically.

```bash
uv run grantguard.py audit /path/to/repo
uv run grantguard.py audit --targets /path/to/repo
uv run grantguard.py audit --targets /repo/a --targets /repo/b
```

Use `--scan` to shallowly discover `.claude/settings*.json` below one or more
target roots:

```bash
uv run grantguard.py audit --scan --targets /path/to/workspace
```

Use `--deep-scan` for deeper discovery under target roots, or without targets
for broad discovery:

```bash
uv run grantguard.py audit --deep-scan --targets /path/to/workspace
uv run grantguard.py audit --deep-scan
```

### Tolerance

```bash
uv run grantguard.py audit --tolerance default
uv run grantguard.py audit --tolerance permissive
```

`default` flags high-risk findings and overbroad wildcard rules. `permissive`
keeps overbroad wildcard rules and flags only higher-risk findings.

### Applying Fixes

`audit` is read-only unless `--fix` is present.

```bash
uv run grantguard.py audit --fix
uv run grantguard.py audit --tolerance permissive --fix
```

`audit --fix` writes to editable Claude settings files in scope and removes all
flagged rules selected by the active tolerance. Managed settings and
`~/.claude.json` are reported as read-only and are not modified.

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No flagged findings, empty audit, or requested fix completed successfully |
| `1` | Findings found in read-only audit, editable findings remain, or a write failed |
| `2` | Invalid CLI usage, such as `--scan` without targets |

## What it flags

| Category | Verdict | Example |
|---|---|---|
| 🔑 Inline credential or API key | remove | `curl -H "Authorization: Bearer <token>" …` |
| 🗝️ Credential-store read | remove | `security find-generic-password *` (macOS), `secret-tool …` (Linux), `cmdkey` (Windows) |
| 💣 Destructive wildcards | remove | `git reset *`, `rm -rf …`, `pkill` |
| 🚀 Unprompted remote push | remove | `git push *` |
| 🌫️ Overly broad wildcards | review | `npm install *`, `gh api *` |
| ✅ Scoped or read-only | keep | `Bash(npm run build)`, `Read(...)` |

Use `--tolerance permissive` to treat the "review" category as safe and act only
on the "remove" categories.

## How it works

GrantGuard parses each settings file and classifies every `allow` rule with regular
expressions. The first matching pattern wins, and the most severe match decides the
verdict. When you apply removals, it rebuilds the `allow` array from the rules you kept
and re-serializes the JSON, so the output is always well-formed.

This is pattern matching, so treat the results as guidance. GrantGuard reports risky
permissions; it cannot block an action while an agent is running. For controls that are
enforced at runtime, deploy an organization-managed `managed-settings.json` with
`permissions.deny` rules and `PreToolUse` hooks, which apply regardless of what the
agent decides. See [`docs/enforced-controls.md`](docs/enforced-controls.md).


## References

GrantGuard is scoped to local Claude Code permission allowlists. It reads settings to classify
`permissions.allow` rules, plus the `allowedTools` entries it knows how to surface from
`~/.claude.json`.

| Claude Code source | Location or pattern | Read by GrantGuard? | Modified by GrantGuard? |
|---|---|---|---|
| User settings | `~/.claude/settings.json` (`%USERPROFILE%\.claude\settings.json` on Windows) | Yes, by default and when passed explicitly | Yes, but only selected `permissions.allow` entries after confirmation or `--fix` |
| Home-local grants | `~/.claude/settings.local.json` | Yes, by default and when passed explicitly | Yes, but only selected `permissions.allow` entries after confirmation or `--fix` |
| Project shared settings | `<repo>/.claude/settings.json` | Yes, when a target repo is passed explicitly or discovered with `--scan` / `--deep-scan` | Yes, but only selected `permissions.allow` entries after confirmation or `--fix` |
| Project local settings | `<repo>/.claude/settings.local.json` | Yes, when a target repo is passed explicitly or discovered with `--scan` / `--deep-scan` | Yes, but only selected `permissions.allow` entries after confirmation or `--fix` |
| Claude state file | `~/.claude.json` | Yes, by default and during broad `--deep-scan`; top-level `allowedTools` and `projects[*].allowedTools` are surfaced, and other state is ignored | No; GrantGuard reports this as read-only because the file also contains unrelated Claude Code state |
| File-based managed settings | macOS `/Library/Application Support/ClaudeCode/managed-settings.json`; Linux/WSL `/etc/claude-code/managed-settings.json`; Windows: GrantGuard currently checks `C:\ProgramData\ClaudeCode\managed-settings.json` | Yes, if the platform-specific file GrantGuard knows about exists | No; GrantGuard reports recognized managed settings as read-only |
| File-based managed drop-ins | `managed-settings.d/*.json` beside `managed-settings.json` | No | No |
| Server-managed settings | Delivered by the Claude.ai admin console, with no local JSON file to inspect | No | No |
| MDM / OS policy settings | macOS `com.anthropic.claudecode` managed preferences; Windows `HKLM` / `HKCU` policy registry | No | No |

## Privacy

GrantGuard runs entirely on your machine. The UI server binds to `127.0.0.1`, makes no
outbound network calls, and the only files it opens are Claude Code settings files
(`.claude/settings*.json`) plus the read-only Claude state file (`~/.claude.json`) when
it is in scope. By default it checks only user-level settings sources. Directory traversal
happens only when you pass `--scan` or `--deep-scan`; broad scans skip generated,
vendored, and tool-managed trees such as dependency caches and editor extensions. On
macOS, scans also skip privacy-sensitive home and `~/Library` folders (Photos, Music,
Documents, Desktop, Downloads, Application Support, Containers, …) to avoid reading
that data or triggering OS privacy prompts. Secrets are redacted in the UI and the CLI. Files
are written only when you confirm a removal or run `audit --fix`. The `/api` endpoints
require a per-session token carried in the launch URL, and the server accepts requests
only from loopback, same-origin callers, which protects the local write endpoint from
DNS-rebinding and cross-site requests.

## Contributing

Contributions are welcome, especially new risk detectors and broader platform coverage.
GrantGuard is standard-library Python with no dependencies, and we want to keep it that
way. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

- Bugs and ideas: open an issue.
- Security reports: see [SECURITY.md](SECURITY.md). Please do not file them publicly.
- Release history: [CHANGELOG.md](CHANGELOG.md).

## A note on where this project stands

GrantGuard started on the product side of Vanta, not in Engineering. It was built by a PM
using agentic tools (Claude Code, and now Codex) to answer a real question: how far can
someone who does not ship production code for a living get toward a genuinely useful,
trustworthy tool, while holding the bar high enough to put Vanta's name on it.

This is an early-stage project, and we want to be clear about that. Vanta's open source work
spans a range: some of it carries the full rigor of Vanta Engineering from day one, and some,
like this, begins as a strong prototype and is engineered up from there. GrantGuard already
does something real (it audits your Claude Code permission grants and flags the risky ones),
and engineers are now involved to steadily raise its quality toward the standard we hold
everything else to. What you are looking at is a project in the process of being leveled up,
and you will see it improve over the weeks and months ahead.

We are open sourcing it at this stage on purpose. Exploring how people outside Engineering can
build real, credible things means doing it in the open. Issues and pull requests are welcome,
and they feed directly into that work.

## Author

Created by **Herman Errico**.

## License

[MIT](LICENSE) © Vanta Inc.

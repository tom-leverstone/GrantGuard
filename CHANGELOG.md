# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-22

Initial release.

### Added
- Classification engine that scans a Claude Code permission allowlist and sorts
  every `allow` rule into **remove** (inline credentials, OS credential-store
  reads, destructive wildcards, unprompted `git push`), **review** (overly broad
  wildcards), or **keep** (scoped / read-only).
- Multi-source auditing: reads the whole precedence chain — user
  (`~/.claude/settings.json`, `settings.local.json`), the current project's
  `.claude` settings, and the read-only managed/enterprise file.
- Local web UI (stdlib `http.server`, no dependencies): a Summary overview with
  a macOS-style breakdown, per-source navigation, and review-then-remove flow.
  Removals happen only on explicit confirmation, written in place (no backup —
  re-approving a removed permission in Claude Code restores it).
- CLI with dry-run by default, `--apply`, `--scan` (opt-in machine sweep),
  `--project`, explicit file/dir arguments, `--keep-overbroad`, and `--show-safe`.
  Exit code `1` when flagged rules are found (handy for CI).
- Cross-platform: macOS, Linux, and Windows (detectors and paths for each).
- Secret redaction in all output.
- Installers for macOS/Linux (`install.sh`) and Windows (`install.ps1`).

### Security
- The local UI server accepts only loopback `Host` values and same-origin
  `Origin`, resisting DNS-rebinding and CSRF against the write endpoint, and
  caps request body size.

[Unreleased]: https://github.com/VantaInc/grantguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/VantaInc/grantguard/releases/tag/v0.1.0

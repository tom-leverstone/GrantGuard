# Security Policy

GrantGuard is a **local, read-only-by-default** tool. It runs a web UI bound to
`127.0.0.1`, reads your Claude Code settings files, and only ever writes when you
explicitly confirm a removal. It makes no network connections of its own.

We still take security seriously and welcome reports.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's **"Report a vulnerability"** button on the
repository's **Security** tab (Security Advisories). If you can't use that,
email **security@vanta.com** with "GrantGuard" in the subject.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (or a proof of concept).
- The version / commit you tested, and your OS.

We'll acknowledge your report within **5 business days** and keep you updated as
we work on a fix. We're happy to credit reporters who want it.

## Supported versions

GrantGuard is pre-1.0; security fixes land on the latest `main` and the most
recent release.

| Version | Supported |
| ------- | --------- |
| latest `main` / newest release | ✅ |
| older releases | ❌ |

## Scope notes

- The UI server enforces loopback-only `Host` and same-origin `Origin` checks to
  resist DNS-rebinding and CSRF against the local write endpoint.
- GrantGuard never transmits the contents of your settings files anywhere; all
  analysis happens locally and secrets are redacted in the UI/CLI output.
- Removing a rule that contained a leaked credential does **not** rotate the
  secret — see the note in the README.

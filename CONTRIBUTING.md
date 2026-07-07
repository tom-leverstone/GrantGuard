# Contributing to GrantGuard

Thanks for your interest! GrantGuard is intentionally small and dependency-free,
and we'd like to keep it that way. Bug fixes, new risk detectors, and platform
coverage are all very welcome.

## Project shape

- **Pure Python 3 standard library** — no runtime dependencies (no pip, no Node).
  Please don't add any. If a change seems to need a dependency, open an issue to
  discuss first.
- `grantguard/core/` — the typed domain model (`types.py`) and behavior:
  `detectors.py` (classification and masking), `tolerance.py`,
  `sources.py` (discovery + documents), `audit.py` (orchestration).
- `grantguard/cli.py` — the command-line interface.
- `grantguard/server.py` — the local web UI server (stdlib `http.server`).
- `grantguard/web/` — the front-end (vanilla HTML/CSS/JS, no build step).

## Local setup

```bash
git clone https://github.com/VantaInc/grantguard.git
cd grantguard
uv run grantguard.py audit     # CLI, dry-run
uv run grantguard.py           # local web UI
```

No install or manually managed virtualenv is required — it's stdlib only. Use
`uv run` as the supported launch path; Python **3.10+** is the floor we target.

## Optional front-end tooling

The front-end is plain JS with no build step, so Node is **not required** to run
or contribute. If you're editing `grantguard/web/`, two optional dev tools keep
the code looking consistent:

- **[tsgo](https://github.com/microsoft/typescript-go)** (`typescript@rc`) — the
  new Go-based TypeScript compiler. We use it in `--checkJs` mode to catch type
  errors in the JS without a compile step.
- **[oxfmt](https://github.com/nicolo-ribaudo/oxfmt)** — a fast JS/TS formatter
  built on oxc.

```bash
pnpm install         # installs both as devDependencies
pnpm check           # type-check grantguard/web/**/*.js (runs tsc --noEmit)
pnpm fmt             # format in-place
pnpm fmt:check       # CI-style check (no writes)
```

If you don't have Node/pnpm, that's fine — CI runs `fmt:check` so any formatting
issues will surface on the PR.

## Before you open a PR

```bash
# everything must at least compile
uv run python -m compileall -q grantguard grantguard.py
```

The test suite is small and **more tests are wanted** (`unittest` from the stdlib
is the natural fit; see `tests/test_detectors.py`). If you add behavior, a small test
for it is the most valuable contribution you can make. CI byte-compiles every
module and runs the tests on macOS, Linux, and Windows on each push and PR:

```bash
uv run python -m unittest discover -s tests
```

## Adding a risk detector

Detectors live in `grantguard/core/detectors.py`.

1. Add your regex to the matching `*_DETECTORS` tuple. Keep word quantifiers bounded
   (`\w{0,64}`, not `\w+`).
2. For a secret, add a `RedactingPatternDetector` to `SECRET_DETECTORS` instead:
   a `pattern` to detect and mask it, plus a `redaction_replacement_template` to
   mask it for display. If the replacement preserves a prefix, make the needed
   capture groups explicit in `pattern`. Add any placeholder it falsely matches
   (e.g. `__TRACKED_VAR__`) to that detector's `allowlist_patterns`.
3. For a new category, also register it in `RiskCategory`, `RISK_CATEGORY_INFO`,
   and `RISK_CATEGORY_ORDER` (`types.py`, where order sets match priority); both
   tables in `tolerance.py` (a missing one crashes the audit); `REASONS`,
   `REASON_SVG`, and `REASON_ORDER` (`web/app.js`); and your new list into
   `PATTERN_DETECTORS`.
4. Add a test in `tests/test_detectors.py`.

## Style & commits

- Match the surrounding style: small functions, clear names, comments only where
  the "why" isn't obvious.
- Keep the front-end framework-free.
- Clear, imperative commit messages. Conventional Commits are welcome but not
  required.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

## Security issues

Don't file security problems as public issues — see [SECURITY.md](SECURITY.md).

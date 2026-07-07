"""Document discovery and concrete PermissionDocument implementations.

Hides file/JSON internals from the audit layer. Discovery functions return
PermissionDocument objects; the audit layer never branches on concrete type.
"""
import json
import os
import platform
from collections.abc import Iterable

from . import detectors
from .types import (
    DiscoveryMethod, PermissionDocument, PermissionDocumentInfo, PermissionRule,
    PermissionScope, RemovalResult, RemovalStatus, RiskCategory, RuleReadResult,
    RuleReadStatus,
)


def managed_settings_path() -> str:
    """Org-enforced managed settings location, per OS (read-only context)."""
    sysname = platform.system()
    if sysname == "Darwin":
        return "/Library/Application Support/ClaudeCode/managed-settings.json"
    if sysname == "Windows":
        return r"C:\ProgramData\ClaudeCode\managed-settings.json"
    return "/etc/claude-code/managed-settings.json"  # Linux & others


class SettingsPermissionDocument:
    """A settings.json / settings.local.json file. Reads & writes permissions.allow.

    Rebuilds the JSON on removal (never string-surgery) so output stays valid. No
    backup is kept: removing an allow rule is non-destructive — Claude just asks
    again next time and the user can re-approve.
    """

    def __init__(self, info: PermissionDocumentInfo):
        self.info = info

    def read_rules(self) -> RuleReadResult:
        try:
            with open(self.info.path) as f:
                data = json.load(f)
            allow = data.get("permissions", {}).get("allow", [])
        except (OSError, ValueError) as exc:
            return RuleReadResult(RuleReadStatus.ERROR_FILE_IO, (), str(exc))
        rules = tuple(PermissionRule(r) for r in allow if isinstance(r, str))
        return RuleReadResult(RuleReadStatus.OK, rules)

    def remove_rules(self, rules: Iterable[PermissionRule]) -> RemovalResult:
        if not self.info.editable:
            return RemovalResult(RemovalStatus.READ_ONLY, 0, None, False,
                                 "source is read-only")
        if os.path.islink(self.info.path):    # CWE-59: never write through a symlink
            return RemovalResult(RemovalStatus.ERROR_FILE_IO, 0, None, False,
                                 "refusing to write through a symlink")
        remove = {r.text for r in rules}
        try:
            with open(self.info.path) as f:
                data = json.load(f)
            allow = data.get("permissions", {}).get("allow", [])
            removed = [r for r in allow if r in remove]
            kept = [r for r in allow if r not in remove]
            if not removed:
                return RemovalResult(RemovalStatus.NO_CHANGES, 0, len(allow), False)
            data.setdefault("permissions", {})["allow"] = kept
            with open(self.info.path, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        except (OSError, ValueError) as exc:
            return RemovalResult(RemovalStatus.ERROR_FILE_IO, 0, None, False, str(exc))
        had_secret = any(
            detectors.apply_detectors(r).category is RiskCategory.SECRET for r in removed
        )
        return RemovalResult(RemovalStatus.APPLIED, len(removed), len(kept), had_secret)


class ClaudeStatePermissionDocument:
    """~/.claude.json allowedTools (top-level + projects[*]). Read-only for removal.

    That file holds lots of unrelated Claude Code state, so grants here are
    surfaced for visibility but never rewritten.
    """

    def __init__(self, info: PermissionDocumentInfo):
        self.info = info

    def read_rules(self) -> RuleReadResult:
        try:
            with open(self.info.path) as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            return RuleReadResult(RuleReadStatus.ERROR_FILE_IO, (), str(exc))
        collected = list(data.get("allowedTools") or [])
        for proj in (data.get("projects") or {}).values():
            if isinstance(proj, dict):
                collected += proj.get("allowedTools") or []
        seen, rules = set(), []
        for a in collected:
            if isinstance(a, str) and a not in seen:
                seen.add(a)
                rules.append(PermissionRule(a))
        return RuleReadResult(RuleReadStatus.OK, tuple(rules))

    def remove_rules(self, rules: Iterable[PermissionRule]) -> RemovalResult:
        return RemovalResult(RemovalStatus.READ_ONLY, 0, None, False,
                             "~/.claude.json is reported read-only")


# ── Discovery ────────────────────────────────────────────────────────────────
# Precedence roles (low->high), with display label and editability.
SCOPE_LABELS = {
    PermissionScope.ENTERPRISE:    ("Managed (enterprise)", False),
    PermissionScope.USER:          ("User",                 True),
    PermissionScope.USER_LOCAL:    ("User (local)",         True),
    PermissionScope.PROJECT:       ("Project (shared)",     True),
    PermissionScope.PROJECT_LOCAL: ("Project (local)",      True),
}


def _settings_doc(path, scope, method, label, editable) -> PermissionDocument:
    return SettingsPermissionDocument(PermissionDocumentInfo(
        path=path, scope=scope, discovered_by=method, label=label, editable=editable))


def _project_root(start_dir):
    """Walk up from start_dir to the nearest directory containing a .claude/ dir."""
    d = os.path.abspath(start_dir)
    home = os.path.expanduser("~")
    while True:
        if os.path.isdir(os.path.join(d, ".claude")):
            return d
        parent = os.path.dirname(d)
        if parent == d or d == home:
            return None
        d = parent


def resolve_project_root(project_dir: str | None = None) -> str | None:
    """Resolve the project root whose .claude settings should be audited."""
    return _project_root(project_dir or os.getcwd())


def discover_precedence_chain(project_dir: str | None = None) -> tuple[PermissionDocument, ...]:
    """Settings files Claude consults (low->high precedence) that exist."""
    home = os.path.expanduser(os.path.join("~", ".claude"))
    candidates = [
        (PermissionScope.ENTERPRISE, managed_settings_path()),
        (PermissionScope.USER, os.path.join(home, "settings.json")),
        (PermissionScope.USER_LOCAL, os.path.join(home, "settings.local.json")),
    ]
    root = resolve_project_root(project_dir)
    if root:
        candidates.append((PermissionScope.PROJECT,
                           os.path.join(root, ".claude", "settings.json")))
        candidates.append((PermissionScope.PROJECT_LOCAL,
                           os.path.join(root, ".claude", "settings.local.json")))
    docs, seen = [], set()
    for scope, path in candidates:
        real = os.path.realpath(path)
        if os.path.exists(path) and real not in seen:
            seen.add(real)
            label, editable = SCOPE_LABELS[scope]
            docs.append(_settings_doc(path, scope, DiscoveryMethod.PRECEDENCE_CHAIN,
                                      label, editable))
    return tuple(docs)


def discover_user_sources() -> tuple[PermissionDocument, ...]:
    """User-level Claude settings sources, without inferring a project."""
    home = os.path.expanduser(os.path.join("~", ".claude"))
    candidates = [
        (PermissionScope.ENTERPRISE, managed_settings_path()),
        (PermissionScope.USER, os.path.join(home, "settings.json")),
        (PermissionScope.USER_LOCAL, os.path.join(home, "settings.local.json")),
    ]
    docs, seen = [], set()
    for scope, path in candidates:
        real = os.path.realpath(path)
        if os.path.exists(path) and real not in seen:
            seen.add(real)
            label, editable = SCOPE_LABELS[scope]
            docs.append(_settings_doc(path, scope, DiscoveryMethod.PRECEDENCE_CHAIN,
                                      label, editable))
    docs.extend(discover_claude_state())
    return tuple(docs)


def _explicit_label(path):
    base = os.path.basename(path)
    return {"settings.local.json": "Local (personal)",
            "settings.json": "Shared"}.get(base, "File")


def resolve_explicit_inputs(inputs: Iterable[str]) -> tuple[PermissionDocument, ...]:
    """Turn explicit files/dirs into documents (a dir expands to its .claude files)."""
    managed = os.path.realpath(managed_settings_path())
    docs, seen = [], set()
    for inp in inputs:
        p = os.path.abspath(os.path.expanduser(inp))
        if os.path.isdir(p):
            claude = p if os.path.basename(p) == ".claude" else os.path.join(p, ".claude")
            cand = [os.path.join(claude, "settings.json"),
                    os.path.join(claude, "settings.local.json")]
        else:
            cand = [p]
        for fp in cand:
            real = os.path.realpath(fp)
            if os.path.exists(fp) and real not in seen:
                seen.add(real)
                if os.path.basename(fp) == ".claude.json":
                    info = PermissionDocumentInfo(
                        path=fp, scope=PermissionScope.CLAUDE_STATE,
                        discovered_by=DiscoveryMethod.EXPLICIT_INPUT,
                        label="User (~/.claude.json · read-only)", editable=False)
                    docs.append(ClaudeStatePermissionDocument(info))
                else:
                    docs.append(_settings_doc(fp, PermissionScope.UNKNOWN,
                                              DiscoveryMethod.EXPLICIT_INPUT,
                                              _explicit_label(fp), real != managed))
    return tuple(docs)


# Folders that never hold first-party .claude settings and/or trigger OS privacy prompts.
VERSION_CONTROL_METADATA_DIRS = frozenset({
    ".git", ".hg", ".svn", ".jj"
})

INSTALLED_DEPENDENCY_DIRS = frozenset({
    "node_modules", "site-packages", "vendor", "Pods", "bower_components",
    "jspm_packages",
})

EDITOR_MANAGED_EXTENSION_DIRS = frozenset({
    ".cursor", ".cursor-server", ".vscode", ".vscode-insiders", ".vscode-server",
})

PYTHON_ENV_AND_CACHE_DIRS = frozenset({
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".nox", ".hypothesis",
    ".ipynb_checkpoints", ".eggs",
})

BUILD_OUTPUT_DIRS = frozenset({
    "dist", "build", "target", ".next", ".nuxt", "DerivedData", "coverage",
    "htmlcov",
})

JAVASCRIPT_TOOL_AND_CACHE_DIRS = frozenset({
    ".bun", ".deno", ".npm", ".pnpm-store", ".yarn", ".parcel-cache",
    ".turbo", ".nx", ".vite", ".svelte-kit", ".angular", ".expo",
    ".nyc_output",
})

TOOLCHAIN_VERSION_MANAGER_DIRS = frozenset({
    ".asdf", ".mise", ".nvm", ".volta", ".fnm", ".pyenv", ".rbenv",
    ".jenv", ".sdkman", ".rustup", ".cargo", ".gradle", ".m2",
    ".terraform",
})

LANGUAGE_PACKAGE_CACHE_DIRS = frozenset({
    ".pipx", ".rye", ".gem", ".pub-cache", ".stack", ".opam", ".conda",
    "miniconda3", "anaconda3", "mambaforge", "micromamba", ".cargo",
    ".rustup"
})

USER_HOME_PRIVATE_DIRS = frozenset({
    "Desktop", "Documents", "Downloads", "Music", "Movies", "Pictures",
    "Photos Library.photoslibrary", "Public", "Mobile Documents", "Library",
    ".Trash",
})

MACOS_HOME_APP_DIRS = frozenset({
    "Applications",
})

MACOS_LIBRARY_PRIVACY_DIRS = frozenset({
    "Application Support", "Caches", "CloudStorage", "Containers",
    "Group Containers", "Keychains", "Logs", "Mail", "Messages",
    "Mobile Documents", "Safari",
})

SCAN_PRUNE_GROUPS = (
    VERSION_CONTROL_METADATA_DIRS,
    INSTALLED_DEPENDENCY_DIRS,
    EDITOR_MANAGED_EXTENSION_DIRS,
    PYTHON_ENV_AND_CACHE_DIRS,
    BUILD_OUTPUT_DIRS,
    JAVASCRIPT_TOOL_AND_CACHE_DIRS,
    TOOLCHAIN_VERSION_MANAGER_DIRS,
    LANGUAGE_PACKAGE_CACHE_DIRS,
)

SCAN_PRUNE = frozenset().union(*SCAN_PRUNE_GROUPS)


def _scan_prune_names(dirpath: str, home: str) -> frozenset[str]:
    """Return child directory names to prune at this exact scan location."""
    prune = SCAN_PRUNE
    if platform.system() != "Darwin":
        return prune

    real_dir = os.path.realpath(dirpath)
    real_home = os.path.realpath(home)
    if real_dir == real_home:
        prune = prune | USER_HOME_PRIVATE_DIRS | MACOS_HOME_APP_DIRS
    elif real_dir == os.path.join(real_home, "Library"):
        # Applies when os.walk reaches ~/Library, including an explicit ~/Library root.
        prune = prune | MACOS_LIBRARY_PRIVACY_DIRS
    return prune


def _scan_roots(extra=None, include_defaults=True):
    home = os.path.expanduser("~")
    roots = []
    if include_defaults:
        roots = [home, os.getcwd()]
        for sub in ("code", "src", "Code", "dev", "Developer", "projects", "repos", "git", "work"):
            roots.append(os.path.join(home, sub))
    if extra:
        roots.extend(os.path.expanduser(r) for r in extra)
    seen, out = set(), []
    for r in roots:
        rp = os.path.realpath(r)
        if os.path.isdir(r) and rp not in seen:
            seen.add(rp)
            out.append(r)
    return out


def _scan_label(path, home):
    base = os.path.basename(path)
    proj = os.path.dirname(os.path.dirname(path))   # repo root holding .claude/
    is_home = os.path.realpath(proj) == os.path.realpath(home)
    if base == "settings.local.json":
        return "User (local)" if is_home else "Local (personal)"
    if base == "settings.json":
        return "User" if is_home else "Shared"
    return "File"


def _sort_docs(docs, home):
    def key(d):
        not_ent = d.info.scope is not PermissionScope.ENTERPRISE
        not_home = (os.path.realpath(os.path.dirname(os.path.dirname(d.info.path)))
                    != os.path.realpath(home))
        return (not_ent, not_home, d.info.path)
    return sorted(docs, key=key)


def scan_documents(extra_roots: Iterable[str] | None = None,
                   max_depth: int = 7, limit: int = 300,
                   include_default_roots: bool = True) -> tuple[PermissionDocument, ...]:
    """Sweep home + project roots for settings files (skipping system folders)."""
    home = os.path.expanduser("~")
    managed = os.path.realpath(managed_settings_path())
    docs, seen = [], set()

    ent = managed_settings_path()
    if os.path.exists(ent):
        docs.append(_settings_doc(ent, PermissionScope.ENTERPRISE,
                                  DiscoveryMethod.FILESYSTEM_SCAN,
                                  "Managed (enterprise)", False))
        seen.add(managed)

    for root in _scan_roots(list(extra_roots) if extra_roots else None,
                            include_defaults=include_default_roots):
        base = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirs, files in os.walk(root):
            if dirpath.count(os.sep) - base >= max_depth:
                dirs[:] = []
                continue
            prune = _scan_prune_names(dirpath, home)
            dirs[:] = [d for d in dirs if d not in prune]
            if os.path.basename(dirpath) == ".claude":
                for fn in ("settings.json", "settings.local.json"):
                    fp = os.path.join(dirpath, fn)
                    real = os.path.realpath(fp)
                    if os.path.exists(fp) and real not in seen:
                        seen.add(real)
                        docs.append(_settings_doc(fp, PermissionScope.UNKNOWN,
                                                  DiscoveryMethod.FILESYSTEM_SCAN,
                                                  _scan_label(fp, home), real != managed))
                        if len(docs) >= limit:
                            return tuple(_sort_docs(docs, home))
    return tuple(_sort_docs(docs, home))


def discover_claude_state() -> tuple[PermissionDocument, ...]:
    """Surface ~/.claude.json grants as one read-only document, if the file exists."""
    path = os.path.expanduser(os.path.join("~", ".claude.json"))
    if not os.path.exists(path):
        return ()
    info = PermissionDocumentInfo(
        path=path, scope=PermissionScope.CLAUDE_STATE,
        discovered_by=DiscoveryMethod.CLAUDE_STATE,
        label="User (~/.claude.json · read-only)", editable=False)
    return (ClaudeStatePermissionDocument(info),)


def validate_scope_targets(targets: Iterable[str] | None) -> None:
    """Raise ValueError naming any target path that does not exist.

    Discovery itself skips missing paths — the CLI deliberately treats them as
    an empty audit. Interactive callers (the web UI's scope endpoint) call this
    first so a typo comes back as a loud error instead of an empty report.
    """
    # No targets means none can be missing; short-circuit before touching the FS.
    if targets is None:
        return
    missing: list[str] = []
    for target in targets:
        if not os.path.exists(os.path.expanduser(target)):
            missing.append(target)
    if missing:
        raise ValueError("path not found: " + ", ".join(missing))


def _split_scan_targets(targets: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition scan targets: directories become walk roots, files are audited
    directly (a settings.json handed to a discovery scan is an explicit input,
    not a root to walk)."""
    dirs: list[str] = []
    files: list[str] = []
    for t in targets:
        if os.path.isfile(os.path.expanduser(t)):
            files.append(t)
        else:
            dirs.append(t)
    return dirs, files


def _merge_documents(*groups: Iterable[PermissionDocument]) -> tuple[PermissionDocument, ...]:
    """Concatenate document groups, deduplicating by realpath (first wins)."""
    docs, seen = [], set()
    for group in groups:
        for d in group:
            real = os.path.realpath(d.info.path)
            if real not in seen:
                seen.add(real)
                docs.append(d)
    return tuple(docs)


def select_documents(targets: Iterable[str] | None = None, scan: bool = False,
                     deep_scan: bool = False) -> tuple[PermissionDocument, ...]:
    """Resolve the CLI/UI target and scan contract into permission documents."""
    target_list = list(targets or [])
    if scan and not target_list:
        raise ValueError("--scan requires at least one TARGET or --targets PATH")
    if scan or (deep_scan and target_list):
        dirs, files = _split_scan_targets(target_list)
        depth = {"max_depth": 3} if scan else {}
        return _merge_documents(
            scan_documents(dirs, include_default_roots=False, **depth),
            resolve_explicit_inputs(files))
    if deep_scan:
        return scan_documents() + discover_claude_state()
    if target_list:
        return resolve_explicit_inputs(target_list)
    return discover_user_sources()

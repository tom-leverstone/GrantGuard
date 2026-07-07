"""Command-line interface for the GrantGuard audit command.

Parses CLI options, resolves audit targets, and prints audit results.
"""
import argparse
import sys

from .core import audit as audit_core
from .core import sources
from .core.tolerance import tolerance_from_name
from .core.types import (
    RISK_CATEGORY_INFO, RISK_CATEGORY_ORDER, RemovalStatus, RuleReadStatus,
)


def _print_source(da, args):
    """Print one document's audit; return (removed_count, had_secret)."""
    info = da.document.info
    print("─" * 70)
    print(f"📄 {info.path}")

    if da.read_result.status is RuleReadStatus.ERROR_FILE_IO:
        print(f"   {info.label}  ·  ⚠️  could not read: {da.read_result.message}")
        return 0, False

    flagged, kept = da.flagged(), da.kept()
    ro = "" if info.editable else "  (read-only)"
    print(f"   {info.label}{ro}  ·  {da.total} rules  ·  "
          f"{len(flagged)} flagged  ·  {len(kept)} keep")
    counts = da.counts
    for category in RISK_CATEGORY_ORDER:
        n = counts.get(category, 0)
        if n:
            ci = RISK_CATEGORY_INFO[category]
            print(f"     {ci.emoji} {ci.label:<44} {n:>3}")

    for a in flagged:
        ci = RISK_CATEGORY_INFO[a.category]
        d = a.display_text
        d = (d[:92] + "…") if len(d) > 93 else d
        print(f"     {ci.emoji} [{a.category.value}] {d}")
    if args.show_safe:
        for a in kept:
            t = a.rule.text
            print(f"     • {(t[:92] + '…') if len(t) > 93 else t}")

    if args.fix and flagged:
        result = da.document.remove_rules(da.removable_rules())
        if result.status is RemovalStatus.APPLIED:
            print(f"   ✓ removed {result.removed}, {result.remaining} remain")
            return result.removed, result.had_secret
        if result.status is RemovalStatus.READ_ONLY:
            print("   ⚠️  read-only source — not modified")
        else:
            print(f"   ⚠️  could not modify: {result.message}")
    elif flagged and not info.editable:
        print("   ⚠️  read-only source — not modified")
    return 0, False


def add_audit_args(ap):
    """Register the ``audit`` flags on ``ap`` (a parser or subparser).

    Kept separate so both the standalone CLI parser (``run``) and the launcher's
    ``audit`` subparser share one definition and can't drift apart.
    """
    ap.add_argument("paths", nargs="*", metavar="TARGET", default=[],
                    help="settings files or repo/.claude directories to audit")
    ap.add_argument("--targets", action="append", default=[], metavar="PATH",
                    help="add a target path (repeatable)")
    scan = ap.add_mutually_exclusive_group()
    scan.add_argument("--scan", action="store_true",
                      help="shallowly discover .claude/settings*.json under target roots")
    scan.add_argument("--deep-scan", action="store_true",
                      help="deeply discover .claude/settings*.json under target roots, "
                           "or broadly when no targets are provided")
    ap.add_argument("--tolerance", choices=("default", "permissive"), default="default",
                    help="risk tolerance for flagged rules")
    ap.add_argument("--fix", action="store_true",
                    help="remove flagged entries from editable settings files")
    ap.add_argument("--show-safe", action="store_true", help="also list kept entries")
    return ap


def _target_paths(args):
    return list(args.paths) + list(args.targets or [])


def _select_documents(args):
    """Resolve the new CLI target/scan contract into PermissionDocuments."""
    return sources.select_documents(_target_paths(args), scan=args.scan,
                                    deep_scan=args.deep_scan)


def run(argv=None):
    ap = add_audit_args(argparse.ArgumentParser(
        prog="grantguard",
        description="🛡️ GrantGuard — audit & clean your Claude Code permission allowlist",
    ))
    return run_args(ap.parse_args(argv))


def run_args(args):
    """Execute an audit from an already-parsed args namespace; return exit code."""
    print("═" * 70)
    print("🛡️  GRANTGUARD  —  Claude Code allowlist audit")
    print(f"    {'FIX (writing changes)' if args.fix else 'dry run — no changes'}")

    try:
        tolerance = tolerance_from_name(args.tolerance)
        documents = _select_documents(args)
    except ValueError as exc:
        print(f"grantguard audit: error: {exc}")
        print("═" * 70)
        return 2

    targets = _target_paths(args)
    if args.scan:
        print("    shallow scan:", ", ".join(targets))
    elif args.deep_scan and targets:
        print("    deep scan:", ", ".join(targets))
    elif args.deep_scan:
        print("    deep scan: broad discovery")
    elif targets:
        print("    targets:", ", ".join(targets))
    else:
        print("    inspecting user-level Claude settings sources")

    report = audit_core.audit_documents(documents, tolerance, project_root=None)
    print(f"    platform: {report.platform}")

    if not report.document_audits:
        print("─" * 70)
        print("No Claude settings sources were found.")
        print("Nothing to audit.")
        print("═" * 70)
        return 0

    total_removed, any_secret, total_flagged, write_failed = 0, False, 0, False
    editable_flagged_after_fix = 0
    for da in report.document_audits:
        flagged = da.flagged()
        total_flagged += len(flagged)
        removed, secret = _print_source(da, args)
        total_removed += removed
        any_secret = any_secret or secret
        if args.fix and flagged and da.document.info.editable and removed < len(flagged):
            editable_flagged_after_fix += len(flagged) - removed
            write_failed = True

    print("═" * 70)
    if args.fix:
        print(f"✅ Removed {total_removed} rule(s) across {len(report.document_audits)} source(s).")
        if any_secret:
            print("🔴 Live credentials removed — ROTATE them; deletion doesn’t un-leak them.")
        print("═" * 70)
        return 1 if write_failed or editable_flagged_after_fix else 0
    print(f"Found {total_flagged} flagged rule(s) across {len(report.document_audits)} source(s). "
          f"Re-run with --fix to remove editable findings, or use the UI: grantguard ui")
    print("═" * 70)
    return 1 if total_flagged else 0   # non-zero = drift (handy for CI)


if __name__ == "__main__":
    sys.exit(run())

#!/usr/bin/env python3
"""
GrantGuard main entrypoint.

Web UI usage:
  uv run grantguard.py ui [TARGET ...] [--targets PATH] [--scan | --deep-scan]

CLI usage:
  uv run grantguard.py audit [TARGET ...] [--targets PATH] [--scan | --deep-scan]
  uv run grantguard.py audit --fix   # write removals to editable settings files
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def handle_serve_ui(args: argparse.Namespace) -> None:
    """Serves the GrantGuard web UI (the `ui` subcommand)."""
    from grantguard.server import serve

    paths = list(args.paths) + list(args.targets or [])
    if args.scan and not paths:
        print("grantguard ui: error: --scan requires at least one TARGET or --targets PATH",
              file=sys.stderr)
        sys.exit(2)

    serve(
        paths=paths or None,
        scan=args.scan,
        deep_scan=args.deep_scan,
        tolerance=args.tolerance,
        port=args.port,
        open_browser=not args.no_open,
    )


def handle_cli_audit(args: argparse.Namespace) -> None:
    """Invokes the GrantGuard CLI audit (the `audit` subcommand)."""
    from grantguard.cli import run_args

    sys.exit(run_args(args))


def create_arg_parser() -> argparse.ArgumentParser:
    """Build the top-level parser with `ui`/`audit` subcommands.

    Using subparsers (instead of slicing sys.argv by hand) keeps each command's
    flags self-describing and lets the parser be exercised in isolation.
    """
    from grantguard import cli

    parser = argparse.ArgumentParser(
        prog="grantguard",
        description="🛡️ GrantGuard — audit & clean your Claude Code permission allowlist",
    )
    sub = parser.add_subparsers(dest="command")

    ui = sub.add_parser("ui", help="open the local web UI (the default command)")
    ui.add_argument("paths", nargs="*", metavar="TARGET", default=[],
                    help="settings files or repo/.claude directories to audit")
    ui.add_argument("--targets", action="append", default=[], metavar="PATH",
                    help="add a target path (repeatable)")
    ui_scan = ui.add_mutually_exclusive_group()
    ui_scan.add_argument("--scan", action="store_true",
                         help="shallowly discover .claude/settings*.json under target roots")
    ui_scan.add_argument("--deep-scan", action="store_true",
                         help="deeply discover .claude/settings*.json under target roots, "
                              "or broadly when no targets are provided")
    ui.add_argument("--tolerance", choices=("default", "permissive"), default="default")
    ui.add_argument("--port", type=int, default=8770)
    ui.add_argument("--no-open", action="store_true")
    ui.set_defaults(func=handle_serve_ui)

    # `audit` reuses cli's flag definitions so the two parsers can't drift apart.
    audit = sub.add_parser(
        "audit",
        help="audit & clean your allowlist (dry run by default)",
        description="🛡️ GrantGuard — audit & clean your Claude Code permission allowlist",
    )
    cli.add_audit_args(audit)
    audit.set_defaults(func=handle_cli_audit)

    return parser


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Default to the `ui` subcommand when none is given — a bare `grantguard` or
    # an options-first invocation like `grantguard --port 8770` still opens the UI.
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv = ["ui", *argv]

    args = create_arg_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

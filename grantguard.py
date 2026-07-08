#!/usr/bin/env python3
"""
GrantGuard entry point for ``uv run grantguard.py``.

Web UI usage:
  uv run grantguard.py ui [TARGET ...] [--targets PATH] [--scan | --deep-scan]

CLI usage:
  uv run grantguard.py audit [TARGET ...] [--targets PATH] [--scan | --deep-scan]
  uv run grantguard.py audit --fix   # write removals to editable settings files
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from grantguard._entry import main  # noqa: E402

if __name__ == "__main__":
    main()

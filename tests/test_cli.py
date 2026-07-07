"""End-to-end CLI behavior over fake Claude settings files."""
import argparse
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard import cli  # noqa: E402
from grantguard.core.audit import AuditReport  # noqa: E402


def _args(argv):
    return cli.add_audit_args(argparse.ArgumentParser()).parse_args(argv)


def _fake_expanduser(home):
    def expand(path):
        if path == "~":
            return home
        if path.startswith("~/") or path.startswith("~\\"):
            return os.path.join(home, path[2:])
        return path
    return expand


class TestCliAudit(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.home = os.path.join(self.dir, "home")
        self.managed = os.path.join(self.dir, "managed-settings.json")
        os.makedirs(os.path.join(self.home, ".claude"), exist_ok=True)
        self.path = os.path.join(self.dir, "settings.json")
        self._write(self.path, ["Bash(npm run build)", "Bash(git push *)",
                                'Bash(export REG_KEY="abcd1234efgh5678ijkl")'])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, path, allow):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"permissions": {"allow": allow}}, f)
        return path

    def _run(self, argv):
        buf = io.StringIO()
        with mock.patch.object(cli.sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(self.home)):
            with mock.patch.object(cli.sources, "managed_settings_path",
                                   return_value=self.managed):
                with redirect_stdout(buf):
                    code = cli.run_args(_args(argv))
        return code, buf.getvalue()

    def test_dry_run_flags_drift_and_writes_nothing(self):
        code, out = self._run([self.path])
        self.assertEqual(code, 1)
        self.assertIn("flagged", out)
        with open(self.path) as f:
            self.assertEqual(len(json.load(f)["permissions"]["allow"]), 3)

    def test_fix_removes_flagged_and_warns_on_secret(self):
        code, out = self._run([self.path, "--fix"])
        self.assertEqual(code, 0)
        with open(self.path) as f:
            self.assertEqual(json.load(f)["permissions"]["allow"], ["Bash(npm run build)"])
        self.assertIn("ROTATE", out)

    def test_permissive_tolerance_keeps_wildcards(self):
        self._write(self.path, ["Bash(npm install *)"])
        code, _ = self._run([self.path, "--tolerance", "permissive"])
        self.assertEqual(code, 0)

    def test_display_never_prints_raw_secret(self):
        _, out = self._run([self.path])
        self.assertNotIn("abcd1234efgh5678ijkl", out)

    def test_missing_input_is_successful_empty_audit(self):
        code, out = self._run([os.path.join(self.dir, "missing.json")])
        self.assertEqual(code, 0)
        self.assertIn("No Claude settings sources were found", out)

    def test_default_uses_user_sources_without_current_project(self):
        user = self._write(os.path.join(self.home, ".claude", "settings.json"),
                           ["Bash(git push *)"])
        state = self._write(os.path.join(self.home, ".claude.json"),
                            ["Bash(rm -rf *)"])
        cwd = os.getcwd()
        repo = os.path.join(self.dir, "repo")
        project = self._write(os.path.join(repo, ".claude", "settings.json"),
                              ["Bash(git push *)"])
        seen = {}

        def fake_audit(documents, tolerance, project_root=None):
            seen["paths"] = [d.info.path for d in documents]
            seen["editable"] = {d.info.path: d.info.editable for d in documents}
            return AuditReport("Test", self.home, project_root, ())

        try:
            os.chdir(repo)
            with mock.patch.object(cli.audit_core, "audit_documents", side_effect=fake_audit):
                self._run([])
        finally:
            os.chdir(cwd)

        self.assertIn(user, seen["paths"])
        self.assertIn(state, seen["paths"])
        self.assertFalse(seen["editable"][state])
        self.assertNotIn(project, seen["paths"])

    def test_empty_default_selection_exits_zero(self):
        code, out = self._run([])
        self.assertEqual(code, 0)
        self.assertIn("No Claude settings sources were found", out)

    def test_targets_flag_matches_positional_target(self):
        pos_code, pos_out = self._run([self.path])
        flag_code, flag_out = self._run(["--targets", self.path])

        self.assertEqual(pos_code, flag_code)
        self.assertEqual(pos_out.count(self.path), flag_out.count(self.path))

    def test_scan_without_targets_is_invalid_usage(self):
        code, out = self._run(["--scan"])
        self.assertEqual(code, 2)
        self.assertIn("--scan requires", out)

    def test_shallow_scan_uses_only_target_roots(self):
        target = self._write(os.path.join(self.dir, "workspace", "repo", ".claude",
                                         "settings.json"), ["Bash(git push *)"])
        outside = self._write(os.path.join(self.home, "code", "repo", ".claude",
                                          "settings.json"), ["Bash(git push *)"])

        code, out = self._run(["--scan", "--targets", os.path.join(self.dir, "workspace")])

        self.assertEqual(code, 1)
        self.assertIn(target, out)
        self.assertNotIn(outside, out)

    def test_deep_scan_without_targets_is_broad_discovery(self):
        target = self._write(os.path.join(self.home, "code", "repo", ".claude",
                                         "settings.json"), ["Bash(git push *)"])

        code, out = self._run(["--deep-scan"])

        self.assertEqual(code, 1)
        self.assertIn(target, out)


if __name__ == "__main__":
    unittest.main()

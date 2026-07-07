"""Tests for the web server's typed audit serialization and apply wiring."""
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard import server  # noqa: E402
from grantguard.core.types import PermissionRule  # noqa: E402


def _fake_expanduser(home):
    def expand(path):
        if path == "~":
            return home
        if path.startswith("~/") or path.startswith("~\\"):
            return os.path.join(home, path[2:])
        return path
    return expand


class TestReportSerialization(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".claude", "settings.json")
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            json.dump({"permissions": {"allow": [
                "Bash(npm run build)", "Bash(git push *)",
                'Bash(export REG_KEY="abcd1234efgh5678ijkl")']}}, f)
        server._cfg.update(paths=[self.path], scan=False, deep_scan=False,
                           tolerance="default", report=None)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)
        server._cfg.update(paths=None, scan=False, deep_scan=False,
                           tolerance="default", report=None)

    def test_serializer_matches_app_js_contract(self):
        data = server._report_to_json(server._build_report())
        self.assertEqual(set(data), {"platform", "home", "project_root", "scope", "sources"})
        self.assertEqual(data["scope"], {"mode": "targets", "targets": [self.path]})
        src = data["sources"][0]
        self.assertTrue({"path", "label", "editable", "total", "counts", "items"} <= set(src))
        item = src["items"][0]
        self.assertTrue({"rule", "display", "reason", "label", "emoji", "tier",
                         "recommend_remove"} <= set(item))
        secret = [i for i in src["items"] if i["reason"] == "SECRET"][0]
        self.assertIn("<REDACTED>", secret["display"])
        self.assertNotIn("abcd1234efgh5678ijkl", secret["display"])      # masked for display
        self.assertEqual(secret["rule"], 'Bash(export REG_KEY="abcd1234efgh5678ijkl")')  # raw kept
        self.assertEqual(secret["tier"], "TOSS")

    def test_default_report_does_not_infer_project_root(self):
        server._cfg.update(paths=[self.path], scan=False, deep_scan=False,
                           tolerance="default", report=None)

        data = server._report_to_json(server._build_report())

        self.assertIsNone(data["project_root"])

    def test_documents_shallow_scan_uses_configured_paths_only(self):
        workspace = os.path.join(self.dir, "workspace")
        target = os.path.join(workspace, "repo", ".claude", "settings.json")
        outside = os.path.join(self.dir, "outside", "repo", ".claude", "settings.json")
        for path in (target, outside):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump({"permissions": {"allow": ["Bash(git push *)"]}}, f)
        server._cfg.update(paths=[workspace], scan=True, deep_scan=False,
                           tolerance="default", report=None)

        docs = server._documents()

        paths = [os.path.realpath(d.info.path) for d in docs]
        self.assertIn(os.path.realpath(target), paths)
        self.assertNotIn(os.path.realpath(outside), paths)

    def test_find_audit_and_document_apply(self):
        report = server._build_report()
        da = server._find_audit(report, self.path)
        assert da is not None  # narrows Optional for the type checker
        result = da.document.remove_rules([PermissionRule("Bash(git push *)")])
        self.assertEqual(result.removed, 1)
        with open(self.path) as f:
            self.assertNotIn("Bash(git push *)", json.load(f)["permissions"]["allow"])

    def test_find_audit_rejects_unknown_path(self):
        report = server._build_report()
        self.assertIsNone(server._find_audit(report, os.path.join(self.dir, "nope.json")))


class TestScopeEndpoint(unittest.TestCase):
    """/api/scope validation and session-config swapping (via _set_scope)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".claude", "settings.json")
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            json.dump({"permissions": {"allow": ["Bash(git push *)"]}}, f)
        server._cfg.update(paths=[self.path], scan=False, deep_scan=False,
                           tolerance="default", report=None)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)
        server._cfg.update(paths=None, scan=False, deep_scan=False,
                           tolerance="default", report=None)

    def _cfg_snapshot(self):
        return {k: server._cfg[k] for k in ("paths", "scan", "deep_scan")}

    def test_rejects_unknown_mode_and_keeps_config(self):
        before = self._cfg_snapshot()
        code, body = server._set_scope("everything", [])
        self.assertEqual(code, 400)
        self.assertIn("mode", body["error"])
        self.assertEqual(self._cfg_snapshot(), before)

    def test_rejects_non_string_targets(self):
        code, body = server._set_scope("targets", [{"path": self.path}])
        self.assertEqual(code, 400)
        self.assertIn("targets", body["error"])

    def test_rejects_scan_without_targets(self):
        code, body = server._set_scope("scan", ["   "])
        self.assertEqual(code, 400)
        self.assertIn("TARGET", body["error"])

    def test_rejects_missing_path_and_keeps_config(self):
        before = self._cfg_snapshot()
        code, body = server._set_scope("targets", [os.path.join(self.dir, "nope")])
        self.assertEqual(code, 400)
        self.assertIn("not found", body["error"])
        self.assertEqual(self._cfg_snapshot(), before)

    def test_scan_modes_audit_file_targets_directly(self):
        # A settings file handed to a discovery scan is an explicit input, not
        # a walk root — the UI's default "discover" depth must work for files.
        for mode in ("scan", "deep-scan"):
            code, body = server._set_scope(mode, [self.path])
            self.assertEqual(code, 200, mode)
            self.assertIn(os.path.realpath(self.path),
                          [os.path.realpath(s["path"]) for s in body["sources"]])

    def test_targets_mode_audits_explicit_file(self):
        code, body = server._set_scope("targets", [self.path])
        self.assertEqual(code, 200)
        self.assertEqual(body["scope"], {"mode": "targets", "targets": [self.path]})
        self.assertEqual([s["path"] for s in body["sources"]], [self.path])
        self.assertEqual(server._cfg["paths"], [self.path])

    def test_scan_mode_discovers_under_directory_only(self):
        workspace = os.path.join(self.dir, "workspace")
        inside = os.path.join(workspace, "repo", ".claude", "settings.json")
        outside = os.path.join(self.dir, "elsewhere", "repo", ".claude", "settings.json")
        for p in (inside, outside):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                json.dump({"permissions": {"allow": ["Bash(git push *)"]}}, f)
        code, body = server._set_scope("scan", [workspace])
        self.assertEqual(code, 200)
        self.assertEqual(body["scope"]["mode"], "scan")
        paths = [os.path.realpath(s["path"]) for s in body["sources"]]
        self.assertIn(os.path.realpath(inside), paths)
        self.assertNotIn(os.path.realpath(outside), paths)
        self.assertTrue(server._cfg["scan"])

    def _set_scope_isolated(self, mode, targets):
        """_set_scope with user-level discovery pinned inside the tempdir, so
        tests never read the real ~/.claude sources of whoever runs them."""
        home = os.path.join(self.dir, "home")
        os.makedirs(home, exist_ok=True)
        with mock.patch.object(server.sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)), \
             mock.patch.object(server.sources, "managed_settings_path",
                               return_value=os.path.join(self.dir, "managed.json")):
            return server._set_scope(mode, targets)

    def test_user_mode_ignores_targets(self):
        code, body = self._set_scope_isolated("user", [self.path])
        self.assertEqual(code, 200)
        self.assertEqual(body["scope"], {"mode": "user", "targets": []})
        self.assertIsNone(server._cfg["paths"])

    def test_scope_change_refreshes_session_report(self):
        server._build_report()
        code, _ = self._set_scope_isolated("user", [])
        self.assertEqual(code, 200)
        self.assertIsNone(server._find_audit(server._cfg["report"], self.path))

    def test_stale_audit_does_not_cache_over_newer_scope(self):
        # An audit that started under an old scope must not clobber the report
        # a mid-flight scope change committed (the "gen" guard).
        other = os.path.join(self.dir, "other", ".claude", "settings.json")
        os.makedirs(os.path.dirname(other))
        with open(other, "w") as f:
            json.dump({"permissions": {"allow": ["Bash(git push *)"]}}, f)
        real_audit = server._audit_scope

        def racing_audit(paths, scan, deep_scan, tolerance):
            report = real_audit(paths, scan, deep_scan, tolerance)
            if not getattr(racing_audit, "raced", False):
                racing_audit.raced = True   # another "thread" swaps the scope
                server._set_scope("targets", [other])
            return report

        with mock.patch.object(server, "_audit_scope", side_effect=racing_audit):
            stale = server._build_report()
        self.assertIsNotNone(server._find_audit(stale, self.path))
        self.assertIsNotNone(server._find_audit(server._cfg["report"], other))
        self.assertIsNone(server._find_audit(server._cfg["report"], self.path))


class TestStaticContainment(unittest.TestCase):
    def test_safe_static_allows_assets_and_rejects_traversal(self):
        self.assertIsNotNone(server._safe_static("app.js"))
        for bad in ("..", "../app.js", "a/b", "x\\y", "C:\\Windows\\win.ini", "/etc/passwd"):
            self.assertIsNone(server._safe_static(bad), bad)


if __name__ == "__main__":
    unittest.main()

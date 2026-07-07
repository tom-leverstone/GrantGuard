"""Tests for concrete permission documents and discovery."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard.core import sources  # noqa: E402
from grantguard.core.types import (  # noqa: E402
    DiscoveryMethod, PermissionDocumentInfo, PermissionRule, PermissionScope,
    RemovalStatus, RuleReadStatus,
)


def _settings_doc(path, editable=True):
    return sources.SettingsPermissionDocument(PermissionDocumentInfo(
        path=path, scope=PermissionScope.UNKNOWN,
        discovered_by=DiscoveryMethod.EXPLICIT_INPUT, label="Test", editable=editable))


def _fake_expanduser(home):
    def expand(path):
        if path == "~":
            return home
        if path.startswith("~/") or path.startswith("~\\"):
            return os.path.join(home, path[2:])
        return path
    return expand


class TestSettingsDocument(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "settings.json")
        self._write(["Bash(npm run build)", "Bash(git push *)",
                     'Bash(export REG_KEY="abcd1234efgh5678ijkl")'])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, allow):
        with open(self.path, "w") as f:
            json.dump({"permissions": {"allow": allow}}, f)

    def test_read_rules_reads_permissions_allow(self):
        res = _settings_doc(self.path).read_rules()
        self.assertIs(res.status, RuleReadStatus.OK)
        self.assertEqual([r.text for r in res.rules],
                         ["Bash(npm run build)", "Bash(git push *)",
                          'Bash(export REG_KEY="abcd1234efgh5678ijkl")'])

    def test_read_rules_bad_json_is_error(self):
        with open(self.path, "w") as f:
            f.write("{ not json")
        res = _settings_doc(self.path).read_rules()
        self.assertIs(res.status, RuleReadStatus.ERROR_FILE_IO)
        self.assertEqual(res.rules, ())

    def test_read_rules_missing_file_is_error(self):
        res = _settings_doc(os.path.join(self.dir, "nope.json")).read_rules()
        self.assertIs(res.status, RuleReadStatus.ERROR_FILE_IO)

    def test_remove_applies_exact_matches_and_flags_secret(self):
        res = _settings_doc(self.path).remove_rules([
            PermissionRule("Bash(git push *)"),
            PermissionRule('Bash(export REG_KEY="abcd1234efgh5678ijkl")'),
        ])
        self.assertIs(res.status, RemovalStatus.APPLIED)
        self.assertEqual(res.removed, 2)
        self.assertEqual(res.remaining, 1)
        self.assertTrue(res.had_secret)
        with open(self.path) as f:
            self.assertEqual(json.load(f)["permissions"]["allow"], ["Bash(npm run build)"])

    def test_remove_nonmatching_is_no_changes(self):
        res = _settings_doc(self.path).remove_rules([PermissionRule("Bash(nope)")])
        self.assertIs(res.status, RemovalStatus.NO_CHANGES)
        self.assertEqual(res.removed, 0)
        self.assertEqual(res.remaining, 3)

    def test_remove_on_readonly_doc_is_read_only_and_writes_nothing(self):
        res = _settings_doc(self.path, editable=False).remove_rules(
            [PermissionRule("Bash(git push *)")])
        self.assertIs(res.status, RemovalStatus.READ_ONLY)
        with open(self.path) as f:
            self.assertEqual(len(json.load(f)["permissions"]["allow"]), 3)  # untouched

    def test_remove_refuses_symlink(self):
        link = os.path.join(self.dir, "settings.local.json")
        try:
            os.symlink(self.path, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not permitted on this platform")
        res = _settings_doc(link).remove_rules([PermissionRule("Bash(git push *)")])
        self.assertIsNot(res.status, RemovalStatus.APPLIED)
        with open(self.path) as f:
            self.assertEqual(len(json.load(f)["permissions"]["allow"]), 3)  # untouched

class TestClaudeStateDocument(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".claude.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _doc(self):
        return sources.ClaudeStatePermissionDocument(PermissionDocumentInfo(
            path=self.path, scope=PermissionScope.CLAUDE_STATE,
            discovered_by=DiscoveryMethod.CLAUDE_STATE,
            label="claude-state", editable=False))

    def test_collects_toplevel_and_per_project_deduped_in_order(self):
        with open(self.path, "w") as f:
            json.dump({"allowedTools": ["mcp__jira__create"],
                       "projects": {"/a": {"allowedTools": ["Bash(git push *)"]},
                                    "/b": {"allowedTools": ["Bash(git push *)",
                                                            "Bash(npm run build)"]}}}, f)
        res = self._doc().read_rules()
        self.assertIs(res.status, RuleReadStatus.OK)
        self.assertEqual([r.text for r in res.rules],
                         ["mcp__jira__create", "Bash(git push *)", "Bash(npm run build)"])

    def test_remove_is_read_only(self):
        with open(self.path, "w") as f:
            json.dump({"allowedTools": ["Bash(git push *)"]}, f)
        res = self._doc().remove_rules([PermissionRule("Bash(git push *)")])
        self.assertIs(res.status, RemovalStatus.READ_ONLY)
        self.assertEqual(res.removed, 0)


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _settings(self, path, allow=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"permissions": {"allow": allow or []}}, f)
        return path

    def test_resolve_explicit_file(self):
        p = self._settings(os.path.join(self.dir, "settings.json"))
        docs = sources.resolve_explicit_inputs([p])
        self.assertEqual(len(docs), 1)
        self.assertIsInstance(docs[0], sources.SettingsPermissionDocument)
        self.assertIs(docs[0].info.discovered_by, DiscoveryMethod.EXPLICIT_INPUT)
        self.assertEqual(docs[0].info.label, "Shared")
        self.assertTrue(docs[0].info.editable)

    def test_resolve_explicit_directory_expands_to_claude_files(self):
        self._settings(os.path.join(self.dir, ".claude", "settings.json"))
        self._settings(os.path.join(self.dir, ".claude", "settings.local.json"))
        docs = sources.resolve_explicit_inputs([self.dir])
        self.assertEqual(sorted(d.info.label for d in docs),
                         ["Local (personal)", "Shared"])

    def test_resolve_explicit_dedupes_same_file(self):
        p = self._settings(os.path.join(self.dir, "settings.json"))
        self.assertEqual(len(sources.resolve_explicit_inputs([p, p])), 1)

    def test_resolve_explicit_claude_state_is_read_only_state_document(self):
        p = os.path.join(self.dir, ".claude.json")
        with open(p, "w") as f:
            json.dump({"allowedTools": ["Bash(git push *)"]}, f)
        docs = sources.resolve_explicit_inputs([p])
        self.assertEqual(len(docs), 1)
        self.assertIsInstance(docs[0], sources.ClaudeStatePermissionDocument)
        self.assertFalse(docs[0].info.editable)

    def test_precedence_chain_includes_project_file(self):
        proj = os.path.join(self.dir, "repo")
        target = self._settings(os.path.join(proj, ".claude", "settings.json"))
        by_path = {os.path.realpath(d.info.path): d
                   for d in sources.discover_precedence_chain(proj)}
        self.assertIn(os.path.realpath(target), by_path)
        self.assertIs(by_path[os.path.realpath(target)].info.scope, PermissionScope.PROJECT)

    def test_user_sources_do_not_infer_project_from_cwd(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        user = self._settings(os.path.join(home, ".claude", "settings.json"))
        repo = os.path.join(self.dir, "repo")
        project = self._settings(os.path.join(repo, ".claude", "settings.json"))
        cwd = os.getcwd()
        try:
            os.chdir(repo)
            with mock.patch.object(sources.os.path, "expanduser",
                                   side_effect=_fake_expanduser(home)):
                docs = sources.discover_user_sources()
        finally:
            os.chdir(cwd)

        paths = [os.path.realpath(d.info.path) for d in docs]
        self.assertIn(os.path.realpath(user), paths)
        self.assertNotIn(os.path.realpath(project), paths)

    def test_select_documents_default_uses_user_sources_without_current_project(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        user = self._settings(os.path.join(home, ".claude", "settings.json"))
        state = os.path.join(home, ".claude.json")
        os.makedirs(os.path.dirname(state), exist_ok=True)
        with open(state, "w") as f:
            json.dump({"allowedTools": ["Bash(git push *)"]}, f)
        repo = os.path.join(self.dir, "repo")
        project = self._settings(os.path.join(repo, ".claude", "settings.json"))
        cwd = os.getcwd()
        try:
            os.chdir(repo)
            with mock.patch.object(sources.os.path, "expanduser",
                                   side_effect=_fake_expanduser(home)):
                docs = sources.select_documents()
        finally:
            os.chdir(cwd)

        paths = [os.path.realpath(d.info.path) for d in docs]
        self.assertIn(os.path.realpath(user), paths)
        self.assertIn(os.path.realpath(state), paths)
        self.assertNotIn(os.path.realpath(project), paths)

    def test_select_documents_explicit_targets_resolve_inputs(self):
        repo = os.path.join(self.dir, "repo")
        target = self._settings(os.path.join(repo, ".claude", "settings.json"))

        docs = sources.select_documents([repo])

        self.assertEqual([os.path.realpath(d.info.path) for d in docs],
                         [os.path.realpath(target)])
        self.assertIs(docs[0].info.discovered_by, DiscoveryMethod.EXPLICIT_INPUT)

    def test_select_documents_explicit_target_with_tilde_segment_is_not_rewritten(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        target = self._settings(os.path.join(self.dir, "RUNNER~1", "settings.json"))

        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)):
            docs = sources.select_documents([target])

        self.assertEqual([os.path.realpath(d.info.path) for d in docs],
                         [os.path.realpath(target)])

    def test_select_documents_shallow_scan_excludes_default_roots(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        target = self._settings(os.path.join(self.dir, "workspace", "repo",
                                             ".claude", "settings.json"))
        outside = self._settings(os.path.join(home, "code", "repo", ".claude",
                                              "settings.json"))

        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)):
            docs = sources.select_documents([os.path.join(self.dir, "workspace")],
                                            scan=True)

        paths = [os.path.realpath(d.info.path) for d in docs]
        self.assertIn(os.path.realpath(target), paths)
        self.assertNotIn(os.path.realpath(outside), paths)

    def test_select_documents_broad_deep_scan_includes_state(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        target = self._settings(os.path.join(home, "code", "repo", ".claude",
                                             "settings.json"))
        state = os.path.join(home, ".claude.json")
        with open(state, "w") as f:
            json.dump({"allowedTools": ["Bash(git push *)"]}, f)

        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)):
            docs = sources.select_documents(deep_scan=True)

        paths = [os.path.realpath(d.info.path) for d in docs]
        self.assertIn(os.path.realpath(target), paths)
        self.assertIn(os.path.realpath(state), paths)

    def test_select_documents_scan_requires_targets(self):
        with self.assertRaisesRegex(ValueError, "--scan requires"):
            sources.select_documents(scan=True)

    def test_select_documents_scan_audits_file_targets_directly(self):
        # Mixed targets: directories are walked, files are explicit inputs.
        workspace = os.path.join(self.dir, "workspace")
        nested = self._settings(os.path.join(workspace, "repo", ".claude", "settings.json"))
        direct = self._settings(os.path.join(self.dir, "solo-settings.json"))
        docs = sources.select_documents([workspace, direct], scan=True)
        paths = [os.path.realpath(d.info.path) for d in docs]
        self.assertIn(os.path.realpath(nested), paths)
        self.assertIn(os.path.realpath(direct), paths)

    def test_select_documents_scan_dedupes_discovered_and_explicit(self):
        workspace = os.path.join(self.dir, "workspace")
        nested = self._settings(os.path.join(workspace, "repo", ".claude", "settings.json"))
        docs = sources.select_documents([workspace, nested], scan=True)
        matches = [d for d in docs
                   if os.path.realpath(d.info.path) == os.path.realpath(nested)]
        self.assertEqual(len(matches), 1)

    def test_validate_scope_targets_names_missing_paths(self):
        present = self._settings(os.path.join(self.dir, "settings.json"))
        sources.validate_scope_targets([present])   # no error
        sources.validate_scope_targets(None)        # no targets, no error
        with self.assertRaisesRegex(ValueError, "path not found: .*missing"):
            sources.validate_scope_targets([present, os.path.join(self.dir, "missing")])

    def test_scan_finds_nested_settings(self):
        import unittest.mock as mock
        target = self._settings(os.path.join(self.dir, "proj", ".claude", "settings.json"))
        with mock.patch.object(sources, "_scan_roots", return_value=[self.dir]):
            docs = sources.scan_documents()
        match = [d for d in docs if os.path.realpath(d.info.path) == os.path.realpath(target)]
        self.assertEqual(len(match), 1)
        self.assertIs(match[0].info.discovered_by, DiscoveryMethod.FILESYSTEM_SCAN)

    def test_scan_prunes_tool_managed_dependency_trees(self):
        target = self._settings(os.path.join(self.dir, "repo", ".claude", "settings.json"))
        bun_cache = self._settings(os.path.join(
            self.dir, ".bun", "install", "cache", "socks", ".claude",
            "settings.local.json"))
        cursor_extension = self._settings(os.path.join(
            self.dir, ".cursor", "extensions", "prettier", ".claude",
            "settings.json"))

        docs = sources.scan_documents([self.dir], include_default_roots=False)

        paths = {os.path.realpath(d.info.path) for d in docs}
        self.assertIn(os.path.realpath(target), paths)
        self.assertNotIn(os.path.realpath(bun_cache), paths)
        self.assertNotIn(os.path.realpath(cursor_extension), paths)

    def test_scan_does_not_globally_prune_private_dir_names(self):
        target = self._settings(os.path.join(
            self.dir, "repo", "Documents", ".claude", "settings.json"))

        docs = sources.scan_documents([self.dir], include_default_roots=False)

        paths = {os.path.realpath(d.info.path) for d in docs}
        self.assertIn(os.path.realpath(target), paths)

    def test_scan_prunes_home_private_dirs_path_aware(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        target = self._settings(os.path.join(
            home, "code", "repo", ".claude", "settings.json"))
        private = self._settings(os.path.join(
            home, "Documents", "repo", ".claude", "settings.json"))

        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)), \
                mock.patch.object(sources.platform, "system", return_value="Darwin"):
            docs = sources.scan_documents([home], include_default_roots=False)

        paths = {os.path.realpath(d.info.path) for d in docs}
        self.assertIn(os.path.realpath(target), paths)
        self.assertNotIn(os.path.realpath(private), paths)

    def test_scan_does_not_prune_home_private_dirs_on_non_macos(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        target = self._settings(os.path.join(
            home, "Documents", "repo", ".claude", "settings.json"))

        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)), \
                mock.patch.object(sources.platform, "system", return_value="Linux"):
            docs = sources.scan_documents([home], include_default_roots=False)

        paths = {os.path.realpath(d.info.path) for d in docs}
        self.assertIn(os.path.realpath(target), paths)

    def test_scan_prunes_library_private_dirs_path_aware(self):
        import unittest.mock as mock
        home = os.path.join(self.dir, "home")
        library = os.path.join(home, "Library")
        target = self._settings(os.path.join(
            library, "Developer", "repo", ".claude", "settings.json"))
        private = self._settings(os.path.join(
            library, "Application Support", "tool", ".claude", "settings.json"))

        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)), \
                mock.patch.object(sources.platform, "system", return_value="Darwin"):
            docs = sources.scan_documents([library], include_default_roots=False)

        paths = {os.path.realpath(d.info.path) for d in docs}
        self.assertIn(os.path.realpath(target), paths)
        self.assertNotIn(os.path.realpath(private), paths)

    def test_discover_claude_state_present_and_absent(self):
        import unittest.mock as mock
        home = self.dir
        with mock.patch.object(sources.os.path, "expanduser",
                               side_effect=_fake_expanduser(home)):
            self.assertEqual(sources.discover_claude_state(), ())
            with open(os.path.join(home, ".claude.json"), "w") as f:
                json.dump({"allowedTools": ["Bash(git push *)"]}, f)
            docs = sources.discover_claude_state()
        self.assertEqual(len(docs), 1)
        self.assertIsInstance(docs[0], sources.ClaudeStatePermissionDocument)
        self.assertIs(docs[0].info.scope, PermissionScope.CLAUDE_STATE)


if __name__ == "__main__":
    unittest.main()

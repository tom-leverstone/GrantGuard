"""Tests for audit orchestration."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard.core.audit import audit_documents  # noqa: E402
from grantguard.core.tolerance import DEFAULT_TOLERANCE, PERMISSIVE_TOLERANCE  # noqa: E402
from grantguard.core.types import (  # noqa: E402
    DiscoveryMethod, PermissionDocumentInfo, PermissionRule, PermissionScope,
    Recommendation, RiskCategory, RuleReadResult, RuleReadStatus,
)


class _FakeDoc:
    """A PermissionDocument whose reads are scripted; audit never writes here."""
    def __init__(self, read_result, editable=True):
        self.info = PermissionDocumentInfo(
            path="/x", scope=PermissionScope.UNKNOWN,
            discovered_by=DiscoveryMethod.EXPLICIT_INPUT, label="X", editable=editable)
        self._read = read_result

    def read_rules(self):
        return self._read

    def remove_rules(self, rules):
        raise NotImplementedError


def _ok(*texts):
    return RuleReadResult(RuleReadStatus.OK, tuple(PermissionRule(t) for t in texts))


class TestAuditDocuments(unittest.TestCase):
    def test_classifies_and_applies_default_tolerance(self):
        doc = _FakeDoc(_ok("Bash(git push *)", "Bash(npm install *)", "Bash(npm run build)"))
        da = audit_documents([doc], DEFAULT_TOLERANCE).document_audits[0]
        self.assertEqual([a.category for a in da.assessments],
                         [RiskCategory.REMOTE_PUSH, RiskCategory.OVERBROAD, RiskCategory.SAFE])
        self.assertEqual([a.recommendation for a in da.assessments],
                         [Recommendation.TOSS, Recommendation.SIDEYE, Recommendation.VIP])
        self.assertEqual([r.text for r in da.removable_rules()],
                         ["Bash(git push *)", "Bash(npm install *)"])

    def test_permissive_keeps_overbroad(self):
        da = audit_documents([_FakeDoc(_ok("Bash(npm install *)"))],
                             PERMISSIVE_TOLERANCE).document_audits[0]
        self.assertIs(da.assessments[0].recommendation, Recommendation.VIP)
        self.assertEqual(da.removable_rules(), ())

    def test_read_failure_is_included_with_no_assessments(self):
        doc = _FakeDoc(RuleReadResult(RuleReadStatus.ERROR_FILE_IO, (), "boom"))
        da = audit_documents([doc], DEFAULT_TOLERANCE).document_audits[0]
        self.assertIs(da.read_result.status, RuleReadStatus.ERROR_FILE_IO)
        self.assertEqual(da.assessments, ())
        self.assertEqual(da.total, 0)

    def test_report_carries_platform_and_home(self):
        report = audit_documents([], DEFAULT_TOLERANCE)
        self.assertTrue(report.platform)
        self.assertTrue(report.home)
        self.assertEqual(report.document_audits, ())

    def test_report_carries_project_root_when_supplied(self):
        report = audit_documents([], DEFAULT_TOLERANCE, project_root="/repo")
        self.assertEqual(report.project_root, "/repo")


if __name__ == "__main__":
    unittest.main()

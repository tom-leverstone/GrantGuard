"""Tests for the GrantGuard core type model."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard.core import types  # noqa: E402
from grantguard.core.audit import (  # noqa: E402
    AuditReport, PermissionDocumentAudit, RuleAssessment,
)
from grantguard.core.detectors import apply_detectors  # noqa: E402
from grantguard.core.types import (  # noqa: E402
    PermissionRule, Recommendation, RiskCategory, RiskCategoryInfo,
    TableAuditTolerance, RuleReadResult, RuleReadStatus,
)


class TestVocabulary(unittest.TestCase):
    def test_permission_rule_preserves_exact_text_and_is_frozen(self):
        r = PermissionRule('Bash(git push *)  ')   # trailing space kept verbatim
        self.assertEqual(r.text, 'Bash(git push *)  ')
        self.assertEqual(r, PermissionRule('Bash(git push *)  '))  # value equality
        with self.assertRaises(Exception):
            r.text = 'mutated'                        # frozen

    def test_category_info_covers_every_category_in_order(self):
        self.assertEqual(
            list(types.RISK_CATEGORY_ORDER),
            [RiskCategory.SECRET, RiskCategory.KEYCHAIN, RiskCategory.DESTRUCTIVE,
             RiskCategory.REMOTE_PUSH, RiskCategory.OVERBROAD, RiskCategory.SAFE],
        )
        for cat in RiskCategory:
            info = types.RISK_CATEGORY_INFO[cat]
            self.assertIsInstance(info, RiskCategoryInfo)
            self.assertEqual(info.category, cat)
            self.assertTrue(info.label and info.emoji)

    def test_table_tolerance_maps_category_to_recommendation(self):
        t = TableAuditTolerance("X", {RiskCategory.OVERBROAD: Recommendation.VIP})
        self.assertIs(t.recommendation_for(RiskCategory.OVERBROAD), Recommendation.VIP)
        self.assertEqual(t.name, "X")


class _FakeDoc:
    """A stand-in PermissionDocument; aggregates never inspect its internals."""
    def __init__(self, info):
        self.info = info
    def read_rules(self):
        raise NotImplementedError
    def remove_rules(self, rules):
        raise NotImplementedError


def _assessment(text, recommendation):
    return RuleAssessment(PermissionRule(text), apply_detectors(text), recommendation)


class TestAggregates(unittest.TestCase):
    def setUp(self):
        self.a_secret = _assessment('Bash(export REG_KEY="abcd1234efgh5678ijkl")',
                                    Recommendation.TOSS)
        self.a_over = _assessment("Bash(npm install *)", Recommendation.SIDEYE)
        self.a_safe = _assessment("Bash(npm run build)", Recommendation.VIP)

    def test_should_remove_is_toss_or_sideye(self):
        self.assertTrue(self.a_secret.should_remove)
        self.assertTrue(self.a_over.should_remove)
        self.assertFalse(self.a_safe.should_remove)

    def test_document_audit_query_helpers(self):
        ok = RuleReadResult(RuleReadStatus.OK,
                            (self.a_secret.rule, self.a_over.rule, self.a_safe.rule))
        da = PermissionDocumentAudit(_FakeDoc(None), ok,
                                     (self.a_secret, self.a_over, self.a_safe))
        self.assertEqual(da.total, 3)
        self.assertEqual(da.counts[RiskCategory.SECRET], 1)
        self.assertEqual([a.category for a in da.flagged()],
                         [RiskCategory.SECRET, RiskCategory.OVERBROAD])
        self.assertEqual([a.category for a in da.kept()], [RiskCategory.SAFE])
        self.assertEqual([r.text for r in da.removable_rules()],
                         ['Bash(export REG_KEY="abcd1234efgh5678ijkl")',
                          "Bash(npm install *)"])

    def test_assessment_display_text_comes_from_detection(self):
        self.assertIn("<REDACTED>", self.a_secret.display_text)
        self.assertNotIn("abcd1234efgh5678ijkl", self.a_secret.display_text)

    def test_failed_read_audit_has_zero_total_and_no_findings(self):
        err = RuleReadResult(RuleReadStatus.ERROR_FILE_IO, (), "boom")
        da = PermissionDocumentAudit(_FakeDoc(None), err, ())
        self.assertEqual(da.total, 0)
        self.assertEqual(da.flagged(), ())
        self.assertEqual(da.counts, {})

    def test_report_flatten_and_findings(self):
        ok = RuleReadResult(RuleReadStatus.OK, (self.a_secret.rule,))
        da_hit = PermissionDocumentAudit(_FakeDoc(None), ok, (self.a_secret,))
        da_clean = PermissionDocumentAudit(_FakeDoc(None), ok, (self.a_safe,))
        report = AuditReport("Linux", "/home/u", None, (da_hit, da_clean))
        self.assertEqual([a.category for a in report.flagged()], [RiskCategory.SECRET])
        self.assertEqual(report.documents_with_findings(), (da_hit,))


if __name__ == "__main__":
    unittest.main()

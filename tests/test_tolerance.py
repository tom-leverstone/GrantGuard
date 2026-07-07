"""Tests for audit tolerance tables."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard.core.tolerance import (  # noqa: E402
    DEFAULT_TOLERANCE, PERMISSIVE_TOLERANCE, tolerance_from_name,
)
from grantguard.core.types import Recommendation, RiskCategory  # noqa: E402


class TestTolerance(unittest.TestCase):
    def test_default_recommends_sideye_for_overbroad(self):
        t = DEFAULT_TOLERANCE
        self.assertIs(t.recommendation_for(RiskCategory.SECRET), Recommendation.TOSS)
        self.assertIs(t.recommendation_for(RiskCategory.OVERBROAD), Recommendation.SIDEYE)
        self.assertIs(t.recommendation_for(RiskCategory.SAFE), Recommendation.VIP)

    def test_permissive_keeps_overbroad(self):
        t = PERMISSIVE_TOLERANCE
        self.assertIs(t.recommendation_for(RiskCategory.OVERBROAD), Recommendation.VIP)
        for cat in (RiskCategory.SECRET, RiskCategory.KEYCHAIN,
                    RiskCategory.DESTRUCTIVE, RiskCategory.REMOTE_PUSH):
            self.assertIs(t.recommendation_for(cat), Recommendation.TOSS)

    def test_both_tables_cover_every_category(self):
        for t in (DEFAULT_TOLERANCE, PERMISSIVE_TOLERANCE):
            for cat in RiskCategory:
                self.assertIsInstance(t.recommendation_for(cat), Recommendation)

    def test_from_name_is_case_insensitive_and_validates(self):
        self.assertIs(tolerance_from_name("default"), DEFAULT_TOLERANCE)
        self.assertIs(tolerance_from_name(" PERMISSIVE "), PERMISSIVE_TOLERANCE)
        with self.assertRaises(ValueError):
            tolerance_from_name("nope")


if __name__ == "__main__":
    unittest.main()

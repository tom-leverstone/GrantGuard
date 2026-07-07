"""Tests for regex-backed rule detection."""
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard.core.detectors import (  # noqa: E402
    MAX_SCAN_LEN,
    PatternDetector,
    RedactingPatternDetector,
    apply_detectors,
)
from grantguard.core.types import RiskCategory  # noqa: E402


def C(text):
    return apply_detectors(text).category


class TestDetectorResult(unittest.TestCase):
    def test_buckets(self):
        cases = {
            'Bash(curl -H "Authorization: Bearer abcd1234efgh5678ijkl" https://x.y)': RiskCategory.SECRET,
            "Bash(security find-generic-password *)": RiskCategory.KEYCHAIN,
            "Bash(git reset *)": RiskCategory.DESTRUCTIVE,
            "Bash(git push *)": RiskCategory.REMOTE_PUSH,
            "Bash(npm install *)": RiskCategory.OVERBROAD,
            "Bash(npm run build)": RiskCategory.SAFE,
            "Read(//tmp/**)": RiskCategory.SAFE,
        }
        for text, expected in cases.items():
            self.assertIs(C(text), expected, text)

    def test_placeholder_not_flagged_as_secret(self):
        self.assertIsNot(C('Bash(curl -H "X-Api-Key: __TRACKED_VAR__" https://x.y)'),
                         RiskCategory.SECRET)

    def test_env_placeholder_not_flagged_as_secret(self):
        self.assertIsNot(C("Bash(export API_TOKEN=__TRACKED_VAR__)"),
                         RiskCategory.SECRET)

    def test_allowlisted_text_outside_match_does_not_suppress_real_secret(self):
        text = (
            'Bash(echo "__TRACKED_VAR__"; '
            'curl -H "Authorization: Bearer abcd1234efgh5678ijkl" https://x.y)'
        )
        result = apply_detectors(text)

        self.assertIs(result.category, RiskCategory.SECRET)
        self.assertIn('echo "__TRACKED_VAR__"', result.masked_text)
        self.assertIn("Bearer <REDACTED>", result.masked_text)

    def test_placeholder_does_not_suppress_real_secret(self):
        text = (
            'Bash(curl -H "X-Api-Key: __TRACKED_VAR__" '
            '-H "Authorization: Bearer abcd1234efgh5678ijkl" https://x.y)'
        )
        result = apply_detectors(text)

        self.assertIs(result.category, RiskCategory.SECRET)
        self.assertIn("X-Api-Key: __TRACKED_VAR__", result.masked_text)
        self.assertIn("Bearer <REDACTED>", result.masked_text)

    def test_shell_substitution_does_not_hide_real_token(self):
        text = 'Bash(curl -H "Authorization: Bearer ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG" $(cat url))'
        self.assertIs(C(text), RiskCategory.SECRET)

    def test_standalone_token_families_are_secrets(self):
        for tok in ("AKIAIOSFODNN7EXAMPLE", "ghp_" + "A" * 36,
                    "sk-" + "B" * 40, "xoxb-123456789012-abcdEFGH"):
            self.assertIs(C("Bash(gh auth login --with-token %s)" % tok),
                          RiskCategory.SECRET, tok)

    def test_secret_beyond_scan_cap_is_truncated_away(self):
        secret = 'export REG_KEY="abcd1234efgh5678ijkl"'
        self.assertIs(C("Bash(%s)" % secret), RiskCategory.SECRET)
        self.assertIs(C("Bash(%s %s)" % ("a" * MAX_SCAN_LEN, secret)), RiskCategory.SAFE)

    def test_backtracking_input_does_not_hang(self):
        big = "KEY" * (MAX_SCAN_LEN // 3)
        start = time.perf_counter()
        self.assertIs(C(big), RiskCategory.SAFE)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_detector_construction_requires_compiled_patterns(self):
        with self.assertRaises(TypeError):
            PatternDetector(
                category=RiskCategory.SAFE,
                pattern=r"raw-string",  # type: ignore[arg-type]
            )

        with self.assertRaises(TypeError):
            RedactingPatternDetector(
                category=RiskCategory.SECRET,
                pattern=r"raw-string",  # type: ignore[arg-type]
                redaction_replacement_template="<REDACTED>",
            )

        with self.assertRaises(TypeError):
            PatternDetector(
                category=RiskCategory.SAFE,
                pattern=re.compile(r"secret"),
                allowlist_patterns=(r"raw-string",),  # type: ignore[list-item]
            )


if __name__ == "__main__":
    unittest.main()

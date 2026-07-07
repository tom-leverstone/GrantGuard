"""Tests for display masking. DetectorResult must mask every secret it flags."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from grantguard.core.detectors import MAX_SCAN_LEN, apply_detectors  # noqa: E402
from grantguard.core.types import RiskCategory  # noqa: E402


class TestRedaction(unittest.TestCase):
    def test_masks_bearer_token(self):
        out = apply_detectors('curl -H "Authorization: Bearer abcd1234efgh5678ijkl"').masked_text
        self.assertIn("<REDACTED>", out)
        self.assertNotIn("abcd1234efgh5678ijkl", out)

    def test_every_detectable_secret_is_masked(self):
        # (label, template, live-token). Each must detect as SECRET *and* have
        # its token absent from the masked output.
        samples = [
            ("Bearer",     'curl -H "Authorization: Bearer {}"', "abcd1234efgh5678ijkl"),
            ("ApiKey",     'curl -H "X-Api-Key: {}"',            "livekey1234567890abcd"),
            ("basic-auth", "curl -u admin:{} https://x.y",       "supersecretpw123"),
            ("env-assign", 'export REG_KEY="{}"',                "abcd1234efgh5678ijkl"),
            ("AWS",        "gh secret set --body {}",            "AKIAIOSFODNN7EXAMPLE"),
            ("GitHub",     "gh auth login --with-token {}",      "ghp_" + "A" * 36),
            ("OpenAI",     "run {}",                             "sk-" + "B" * 40),
            ("Slack",      "post {}",                            "xoxb-123456789012-abcdEFGH"),
        ]
        for label, template, token in samples:
            result = apply_detectors(template.format(token))
            self.assertIs(result.category, RiskCategory.SECRET, label)
            masked = result.masked_text
            self.assertNotIn(token, masked, label)
            self.assertIn("<REDACTED>", masked, label)

    def test_huge_input_is_bounded_by_scan_cap(self):
        self.assertLessEqual(len(apply_detectors("KEY" * 500_000).masked_text), MAX_SCAN_LEN)


if __name__ == "__main__":
    unittest.main()

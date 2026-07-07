"""Regex-backed detection of permission rules.

Owns the PatternDetector registry used for classification and display masking,
so a detected secret shape can never drift from its masked shape. Detector
safety details (the scan cap) live here, not on PermissionRule.
"""
import re
from dataclasses import dataclass, field

from .types import RISK_CATEGORY_ORDER, RiskCategory

# Cap the length any regex sees, so an adversarial multi-MB rule string can't
# drive super-linear backtracking (real allow rules are short). Defense-in-depth
# alongside the bounded quantifiers below.
MAX_SCAN_LEN = 4096


@dataclass(frozen=True)
class PatternDetector:
    """One rule pattern: category plus the compiled regex detection uses."""
    category: RiskCategory
    pattern: re.Pattern[str]
    allowlist_patterns: tuple[re.Pattern[str], ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        _require_compiled_pattern("pattern", self.pattern)
        for index, allowlist_pattern in enumerate(self.allowlist_patterns):
            _require_compiled_pattern(
                f"allowlist_patterns[{index}]",
                allowlist_pattern,
            )

    def matches(self, s: str) -> bool:
        for match in self.pattern.finditer(s[:MAX_SCAN_LEN]):
            matched_text = match.group(0)
            for allowlist_pattern in self.allowlist_patterns:
                if allowlist_pattern.search(matched_text):
                    break
            else:
                return True
        return False

    def mask_text(self, s: str) -> str:
        return s


@dataclass(frozen=True)
class RedactingPatternDetector(PatternDetector):
    """A detector that uses its pattern for both matching and display masking."""
    redaction_replacement_template: str

    def mask_text(self, s: str) -> str:
        def replacement(match: re.Match[str]) -> str:
            matched_text = match.group(0)
            for allowlist_pattern in self.allowlist_patterns:
                if allowlist_pattern.search(matched_text):
                    return matched_text
            return match.expand(self.redaction_replacement_template)

        return self.pattern.sub(replacement, s[:MAX_SCAN_LEN])


def _require_compiled_pattern(name: str, value: re.Pattern[str]) -> None:
    if not isinstance(value, re.Pattern):
        raise TypeError(f"{name} must be a compiled re.Pattern")


CATEGORY_PRIORITY = {
    category: index for index, category in enumerate(RISK_CATEGORY_ORDER)
}


@dataclass(frozen=True)
class DetectorResult:
    text: str
    matches: tuple[PatternDetector, ...]

    @property
    def category(self) -> RiskCategory:
        """Return the highest-priority matched category, or SAFE if no match."""
        if not self.matches:
            return RiskCategory.SAFE
        return min(
            (detector.category for detector in self.matches),
            key=lambda category: CATEGORY_PRIORITY[category],
        )

    @property
    def masked_text(self) -> str:
        """Return the text with all matching detectors' redactions applied."""
        masked = self.text[:MAX_SCAN_LEN]
        for detector in self.matches:
            masked = detector.mask_text(masked)
        return masked


# For `\w` word matching, use {0,64} bounded quantifiers. Redacting detectors
# use the same pattern for detection and masking; replacement templates rely on
# the pattern's capture groups where they preserve prefixes.
SECRET_DETECTORS: list[PatternDetector] = [
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{16,}"),
        redaction_replacement_template=r"\1<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(
            r"((?:X-API-KEY|ApiKey|X-Api-Key|api[_-]?key)\s*[:=]\s*[\"']?)[A-Za-z0-9:_\-]{12,}"
        ),
        allowlist_patterns=(re.compile(r"\b__TRACKED_VAR__\b"),),
        redaction_replacement_template=r"\1<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(
            r"(-u\s+[\"']?[^\"'\s:$]+:)[A-Za-z0-9:_\-\.]{8,}"
        ),
        redaction_replacement_template=r"\1<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(
            r"((?:export\s+)?\w{0,64}(?:KEY|TOKEN|SECRET|PASSWORD)\w{0,64}\s*=\s*[\"']?)[A-Za-z0-9:_\-\.]{12,}"
        ),
        allowlist_patterns=(
            re.compile(r"\bDEMO_KEY\b"),
            re.compile(r"\b__TRACKED_VAR__\b"),
        ),
        redaction_replacement_template=r"\1<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        redaction_replacement_template="<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
        redaction_replacement_template="<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(r"sk-[A-Za-z0-9]{20,}"),
        redaction_replacement_template="<REDACTED>",
    ),
    RedactingPatternDetector(
        category=RiskCategory.SECRET,
        pattern=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        redaction_replacement_template="<REDACTED>",
    ),
]

# OS credential stores — all platforms included, so an allowlist made on one OS
# is still caught when audited on another.
KEYCHAIN_DETECTORS = [
    PatternDetector(
        category=RiskCategory.KEYCHAIN,
        pattern=re.compile(pattern_source),
    )
    for pattern_source in (
        r"security\s+find-(?:generic|internet)-password",   # macOS
        r"\bsecret-tool\b",                                  # Linux libsecret
        r"\bkeyring\s+get\b",                                # Linux python-keyring
        r"\bcmdkey\b",                                       # Windows
        r"Get-StoredCredential|Get-Secret\b",               # Windows PowerShell
    )
]

DESTRUCTIVE_DETECTORS = [
    PatternDetector(
        category=RiskCategory.DESTRUCTIVE,
        pattern=re.compile(pattern_source),
    )
    for pattern_source in (
        r"\brm\s+-[A-Za-z]*[rf]",                            # rm -rf / rm -f
        r"\brmdir\s+/s",                                     # Windows recursive rmdir
        r"\bdel\s+/[a-z]",                                   # Windows del /q /s
        r"Remove-Item\b.*-Recurse",                          # PowerShell
        r"git\s+reset\s+\*",
        r"git\s+rebase\s+\*",
        r"\bkill\s+-9\b",
        r"\bpkill\b",
        r"\bxargs\s+kill",
        r"\bmkfs\b|\bdd\s+if=",
        r":\s*\(\)\s*\{",                                    # fork-bomb shape
    )
]

REMOTE_PUSH_DETECTORS = [
    PatternDetector(
        category=RiskCategory.REMOTE_PUSH,
        pattern=re.compile(pattern_source),
    )
    for pattern_source in (
        r"git\s+push\s+\*", r"git\s+push\s+origin", r"git\s+push\b",
    )
]

OVERBROAD_DETECTORS = [
    PatternDetector(
        category=RiskCategory.OVERBROAD,
        pattern=re.compile(pattern_source),
    )
    for pattern_source in (
        r"^Bash\((?:sudo\s+)?[\w./\\-]+\s+\*\)$",            # `tool *`
        r"git\s+(?:clone|add|commit|fetch|merge|pull|checkout|ls-remote|rev-list|ls-tree)\s+\*",
        r"(?:npm|pip|pip3|npx|gh|cargo|brew|apt|yum|choco)\b.*\*",
        r"chmod\s+\+x",
    )
]

PATTERN_DETECTORS = (
    SECRET_DETECTORS
    + KEYCHAIN_DETECTORS
    + DESTRUCTIVE_DETECTORS
    + REMOTE_PUSH_DETECTORS
    + OVERBROAD_DETECTORS
)

def apply_detectors(rule_text: str) -> DetectorResult:
    """Return all detectors that match a rule, in registry order."""

    return DetectorResult(
        rule_text,
        tuple(detector for detector in PATTERN_DETECTORS if detector.matches(rule_text)),
    )

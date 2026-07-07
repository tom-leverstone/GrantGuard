"""Core domain types for GrantGuard.

Vocabulary, document records, and protocols. This module owns no behavior: it
does not read or write files, detect risk categories, mask strings, or hold
regexes. Those live in detectors.py, tolerance.py, sources.py, and audit.py.
"""
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class RiskCategory(Enum):
    """What classification detected for a rule."""
    SECRET = "SECRET"
    KEYCHAIN = "KEYCHAIN"
    DESTRUCTIVE = "DESTRUCTIVE"
    REMOTE_PUSH = "REMOTE_PUSH"
    OVERBROAD = "OVERBROAD"
    SAFE = "SAFE"


class Recommendation(Enum):
    """What GrantGuard advises doing with a category under a tolerance."""
    TOSS = "TOSS"      # harmful — remove
    SIDEYE = "SIDEYE"  # not great — remove unless kept explicitly
    VIP = "VIP"        # fine — keep


@dataclass(frozen=True)
class RiskCategoryInfo:
    """Display vocabulary for a category — no default recommendation."""
    category: RiskCategory
    label: str
    emoji: str


RISK_CATEGORY_INFO: Mapping[RiskCategory, RiskCategoryInfo] = {
    RiskCategory.SECRET:      RiskCategoryInfo(RiskCategory.SECRET,      "Inline credential / API key in plaintext",     "🔑"),
    RiskCategory.KEYCHAIN:    RiskCategoryInfo(RiskCategory.KEYCHAIN,    "Reads OS credential store without a prompt",    "🗝️"),
    RiskCategory.DESTRUCTIVE: RiskCategoryInfo(RiskCategory.DESTRUCTIVE, "Destructive / irreversible wildcard",          "💣"),
    RiskCategory.REMOTE_PUSH: RiskCategoryInfo(RiskCategory.REMOTE_PUSH, "Pushes code to a remote with no prompt",       "🚀"),
    RiskCategory.OVERBROAD:   RiskCategoryInfo(RiskCategory.OVERBROAD,   "Overly broad wildcard (whole command family)", "🌫️"),
    RiskCategory.SAFE:        RiskCategoryInfo(RiskCategory.SAFE,        "Scoped / read-only / harmless",                "✅"),
}

RISK_CATEGORY_ORDER: tuple[RiskCategory, ...] = (
    RiskCategory.SECRET, RiskCategory.KEYCHAIN, RiskCategory.DESTRUCTIVE,
    RiskCategory.REMOTE_PUSH, RiskCategory.OVERBROAD, RiskCategory.SAFE,
)


@dataclass(frozen=True)
class PermissionRule:
    """The exact allow-rule string read from a permission-bearing document.

    `text` is the removal identity and must be preserved unchanged. Scan-length
    caps and other safety details belong in detector modules.
    """
    text: str


class AuditTolerance(Protocol):
    """A strategy mapping a detected category to a recommendation."""
    @property
    def name(self) -> str:
        ...

    def recommendation_for(self, category: RiskCategory) -> Recommendation:
        ...


@dataclass(frozen=True)
class TableAuditTolerance:
    name: str
    recommendations: Mapping[RiskCategory, Recommendation]

    def recommendation_for(self, category: RiskCategory) -> Recommendation:
        return self.recommendations[category]


class PermissionScope(Enum):
    ENTERPRISE = "enterprise"
    USER = "user"
    USER_LOCAL = "user-local"
    PROJECT = "project"
    PROJECT_LOCAL = "project-local"
    CLAUDE_STATE = "claude-state"
    UNKNOWN = "unknown"


class DiscoveryMethod(Enum):
    PRECEDENCE_CHAIN = "precedence-chain"
    EXPLICIT_INPUT = "explicit-input"
    FILESYSTEM_SCAN = "filesystem-scan"
    CLAUDE_STATE = "claude-state"


@dataclass(frozen=True)
class PermissionDocumentInfo:
    path: str
    scope: PermissionScope
    discovered_by: DiscoveryMethod
    label: str
    editable: bool


class RuleReadStatus(Enum):
    OK = "OK"
    ERROR_FILE_IO = "ERROR_FILE_IO"


@dataclass(frozen=True)
class RuleReadResult:
    status: RuleReadStatus
    rules: tuple[PermissionRule, ...]
    message: str | None = None


class RemovalStatus(Enum):
    APPLIED = "APPLIED"
    READ_ONLY = "READ_ONLY"
    NO_CHANGES = "NO_CHANGES"
    ERROR_FILE_IO = "ERROR_FILE_IO"


@dataclass(frozen=True)
class RemovalResult:
    status: RemovalStatus
    removed: int
    remaining: int | None
    had_secret: bool
    message: str | None = None


class PermissionDocument(Protocol):
    info: PermissionDocumentInfo

    def read_rules(self) -> RuleReadResult:
        ...

    def remove_rules(self, rules: Iterable[PermissionRule]) -> RemovalResult:
        ...

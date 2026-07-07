"""Audit tolerance objects: one category -> recommendation table per mode.

No regexes, no file IO, no redaction, no orchestration.
"""
from .types import (
    AuditTolerance, Recommendation, RiskCategory, TableAuditTolerance,
)

_TOSS, _SIDEYE, _VIP = Recommendation.TOSS, Recommendation.SIDEYE, Recommendation.VIP

DEFAULT_TOLERANCE = TableAuditTolerance(
    name="DEFAULT",
    recommendations={
        RiskCategory.SECRET: _TOSS,
        RiskCategory.KEYCHAIN: _TOSS,
        RiskCategory.DESTRUCTIVE: _TOSS,
        RiskCategory.REMOTE_PUSH: _TOSS,
        RiskCategory.OVERBROAD: _SIDEYE,
        RiskCategory.SAFE: _VIP,
    },
)

PERMISSIVE_TOLERANCE = TableAuditTolerance(
    name="PERMISSIVE",
    recommendations={
        RiskCategory.SECRET: _TOSS,
        RiskCategory.KEYCHAIN: _TOSS,
        RiskCategory.DESTRUCTIVE: _TOSS,
        RiskCategory.REMOTE_PUSH: _TOSS,
        RiskCategory.OVERBROAD: _VIP,
        RiskCategory.SAFE: _VIP,
    },
)

_BY_NAME = {"default": DEFAULT_TOLERANCE, "permissive": PERMISSIVE_TOLERANCE}


def tolerance_from_name(name: str) -> AuditTolerance:
    """Resolve 'default'/'permissive' (case-insensitive) to a tolerance."""
    try:
        return _BY_NAME[name.strip().lower()]
    except KeyError:
        raise ValueError(
            "unknown tolerance: %r (expected 'default' or 'permissive')" % (name,)
        )

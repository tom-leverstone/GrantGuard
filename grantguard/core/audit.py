"""Audit orchestration: documents + tolerance -> AuditReport.

Never understands document internals — it only reads typed results, detects
risk categories, and maps categories to recommendations.
"""
import os
import platform
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .detectors import DetectorResult, apply_detectors
from .types import (
    AuditTolerance, PermissionDocument, PermissionRule, Recommendation,
    RiskCategory, RuleReadResult, RuleReadStatus,
)


@dataclass(frozen=True)
class RuleAssessment:
    rule: PermissionRule
    detection: DetectorResult
    recommendation: Recommendation

    @property
    def category(self) -> RiskCategory:
        return self.detection.category

    @property
    def display_text(self) -> str:
        return self.detection.masked_text

    @property
    def should_remove(self) -> bool:
        return self.recommendation in (Recommendation.TOSS, Recommendation.SIDEYE)


@dataclass(frozen=True)
class PermissionDocumentAudit:
    document: PermissionDocument
    read_result: RuleReadResult
    assessments: tuple[RuleAssessment, ...]

    @property
    def total(self) -> int:
        return len(self.assessments)

    @property
    def counts(self) -> Mapping[RiskCategory, int]:
        out: dict[RiskCategory, int] = {}
        for a in self.assessments:
            out[a.category] = out.get(a.category, 0) + 1
        return out

    def flagged(self) -> tuple[RuleAssessment, ...]:
        return tuple(a for a in self.assessments if a.should_remove)

    def kept(self) -> tuple[RuleAssessment, ...]:
        return tuple(a for a in self.assessments if not a.should_remove)

    def removable_rules(self) -> tuple[PermissionRule, ...]:
        return tuple(a.rule for a in self.flagged())


@dataclass(frozen=True)
class AuditReport:
    platform: str
    home: str
    project_root: str | None
    document_audits: tuple[PermissionDocumentAudit, ...]

    def flagged(self) -> tuple[RuleAssessment, ...]:
        out: list[RuleAssessment] = []
        for da in self.document_audits:
            out.extend(da.flagged())
        return tuple(out)

    def documents_with_findings(self) -> tuple[PermissionDocumentAudit, ...]:
        return tuple(da for da in self.document_audits if da.flagged())


def audit_documents(documents: Iterable[PermissionDocument],
                    tolerance: AuditTolerance,
                    project_root: str | None = None) -> AuditReport:
    """Read, detect, and recommend across documents, preserving read failures."""
    audits = []
    for doc in documents:
        read = doc.read_rules()
        assessments = []
        if read.status is RuleReadStatus.OK:
            for rule in read.rules:
                detection = apply_detectors(rule.text)
                recommendation = tolerance.recommendation_for(detection.category)
                assessments.append(RuleAssessment(rule, detection, recommendation))
        audits.append(PermissionDocumentAudit(doc, read, tuple(assessments)))
    return AuditReport(
        platform=platform.system(),
        home=os.path.expanduser("~"),
        project_root=project_root,
        document_audits=tuple(audits),
    )

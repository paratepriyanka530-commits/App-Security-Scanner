"""Pure cross-validation of existing static and AI finding outputs."""

from pydantic import BaseModel, Field, field_validator

from ai_analysis.schemas import AIFinding
from ai_analysis.validation.matcher import findings_match
from ai_analysis.validation.models import Severity, ValidatedFinding


_SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class _StaticFinding(BaseModel):
    finding_id: str | None = None
    endpoint: str
    method: str
    rule: str
    owasp_category: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("endpoint", "method", "rule", "owasp_category", "evidence")
    @classmethod
    def reject_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


def _higher_severity(static_severity: Severity, ai_severity: Severity) -> Severity:
    if _SEVERITY_ORDER[static_severity] >= _SEVERITY_ORDER[ai_severity]:
        return static_severity
    return ai_severity


def _display_category(static_category: str, ai_category: str) -> str:
    """Prefer the more descriptive equivalent label for report output."""
    if len(ai_category.strip()) > len(static_category.strip()):
        return ai_category
    return static_category


def _combined_confidence(static_confidence: float, ai_confidence: float) -> float:
    return 1.0 - ((1.0 - static_confidence) * (1.0 - ai_confidence))


def _confirmed(
    static_finding: _StaticFinding,
    ai_finding: AIFinding,
) -> ValidatedFinding:
    return ValidatedFinding(
        endpoint=static_finding.endpoint,
        method=static_finding.method,
        vulnerability=static_finding.rule,
        owasp_category=_display_category(
            static_finding.owasp_category,
            ai_finding.owasp_category,
        ),
        severity=_higher_severity(static_finding.severity, ai_finding.severity),
        confidence=_combined_confidence(
            static_finding.confidence,
            ai_finding.confidence,
        ),
        detected_by="BOTH",
        validation_status="CONFIRMED",
        static_evidence=static_finding.evidence,
        ai_evidence=ai_finding.evidence,
        static_rule=static_finding.rule,
        ai_rule=ai_finding.rule,
        static_confidence=static_finding.confidence,
        ai_confidence=ai_finding.confidence,
    )


def _static_only(static_finding: _StaticFinding) -> ValidatedFinding:
    return ValidatedFinding(
        endpoint=static_finding.endpoint,
        method=static_finding.method,
        vulnerability=static_finding.rule,
        owasp_category=static_finding.owasp_category,
        severity=static_finding.severity,
        confidence=static_finding.confidence,
        detected_by="STATIC",
        validation_status="RETAINED",
        static_evidence=static_finding.evidence,
        static_rule=static_finding.rule,
        static_confidence=static_finding.confidence,
    )


def _ai_only(ai_finding: AIFinding) -> ValidatedFinding:
    return ValidatedFinding(
        endpoint=ai_finding.endpoint,
        method=ai_finding.method,
        vulnerability=ai_finding.rule,
        owasp_category=ai_finding.owasp_category,
        severity=ai_finding.severity,
        confidence=ai_finding.confidence,
        detected_by="AI",
        validation_status="MANUAL_REVIEW",
        ai_evidence=ai_finding.evidence,
        ai_rule=ai_finding.rule,
        ai_confidence=ai_finding.confidence,
    )


def cross_validate_findings(
    static_findings: list[dict],
    ai_findings: list[AIFinding],
) -> list[ValidatedFinding]:
    """Pair matching findings one-to-one and retain all unmatched findings."""
    if not isinstance(static_findings, list):
        raise TypeError("static_findings must be a list")
    if not isinstance(ai_findings, list):
        raise TypeError("ai_findings must be a list")

    validated_static = [
        _StaticFinding.model_validate(finding)
        for finding in static_findings
    ]
    validated_ai = [
        finding
        if isinstance(finding, AIFinding)
        else AIFinding.model_validate(finding)
        for finding in ai_findings
    ]

    results: list[ValidatedFinding] = []
    matched_ai_indexes: set[int] = set()

    for static_finding in validated_static:
        matching_index = next(
            (
                index
                for index, ai_finding in enumerate(validated_ai)
                if index not in matched_ai_indexes
                and findings_match(static_finding, ai_finding)
            ),
            None,
        )

        if matching_index is None:
            results.append(_static_only(static_finding))
        else:
            matched_ai_indexes.add(matching_index)
            results.append(
                _confirmed(static_finding, validated_ai[matching_index])
            )

    results.extend(
        _ai_only(ai_finding)
        for index, ai_finding in enumerate(validated_ai)
        if index not in matched_ai_indexes
    )
    return results

"""Report-ready models for cross-validated security findings."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ValidatedFinding(BaseModel):
    """A finding retained after deterministic static/AI comparison."""

    endpoint: str
    method: str
    vulnerability: str
    owasp_category: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    detected_by: Literal["STATIC", "AI", "BOTH"]
    validation_status: Literal["CONFIRMED", "RETAINED", "MANUAL_REVIEW"]
    static_evidence: str | None = None
    ai_evidence: str | None = None
    static_rule: str | None = None
    ai_rule: str | None = None
    static_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    ai_confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("method must not be empty")
        return value.upper()

    @field_validator("endpoint", "vulnerability", "owasp_category")
    @classmethod
    def reject_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

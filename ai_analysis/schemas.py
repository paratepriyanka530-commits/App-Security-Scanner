"""Data contracts for AI-generated security analysis."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class AIFinding(BaseModel):
    """A single semantic security finding produced by the AI detector."""

    endpoint: str
    method: str
    rule: str
    owasp_category: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    detected_by: Literal["AI"] = "AI"

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("rule", "owasp_category", "evidence")
    @classmethod
    def reject_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class AIAnalysisResult(BaseModel):
    """AI analysis outcome for one normalized API endpoint."""

    endpoint: str
    method: str
    status: Literal["SAFE", "POTENTIAL_VULNERABILITY"]
    findings: list[AIFinding] = Field(default_factory=list)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def validate_result_consistency(self):
        if self.status == "SAFE" and self.findings:
            raise ValueError("SAFE results must not contain findings")
        if self.status == "POTENTIAL_VULNERABILITY" and not self.findings:
            raise ValueError(
                "POTENTIAL_VULNERABILITY results must contain at least one finding"
            )

        for finding in self.findings:
            if finding.endpoint != self.endpoint:
                raise ValueError(
                    "finding endpoint must match the analysis result endpoint"
                )
            if finding.method != self.method:
                raise ValueError(
                    "finding method must match the analysis result method"
                )

        return self

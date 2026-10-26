"""Data contracts for deterministic endpoint-level evaluation."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class GroundTruthLabel(BaseModel):
    """One safe endpoint label or one endpoint/category vulnerability label."""

    endpoint: str
    method: str
    owasp_category: str | None = None
    vulnerable: bool

    @field_validator("endpoint", "method")
    @classmethod
    def reject_empty_identity(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def validate_category_consistency(self):
        if self.vulnerable:
            if self.owasp_category is None or not self.owasp_category.strip():
                raise ValueError("vulnerable labels require an OWASP category")
        elif self.owasp_category is not None:
            raise ValueError("safe labels must not contain an OWASP category")
        return self


class EvaluationPrediction(BaseModel):
    """A configuration-independent endpoint/category prediction."""

    endpoint: str
    method: str
    owasp_category: str | None = None
    detected: bool
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source: Literal["STATIC", "AI", "HYBRID"] | None = None

    @field_validator("endpoint", "method")
    @classmethod
    def reject_empty_identity(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def validate_category_consistency(self):
        if self.detected:
            if self.owasp_category is None or not self.owasp_category.strip():
                raise ValueError("detected predictions require an OWASP category")
        elif self.owasp_category is not None:
            raise ValueError("non-detections must not contain an OWASP category")
        return self


class ConfusionCounts(BaseModel):
    """Non-negative classification counts."""

    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    true_negative: int = Field(ge=0)


class EvaluationResult(BaseModel):
    """Counts and unrounded metrics for one detector configuration."""

    confusion_counts: ConfusionCounts
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1_score: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    accuracy: float = Field(ge=0.0, le=1.0)

    @property
    def counts(self) -> ConfusionCounts:
        """Concise alias for callers that prefer result.counts."""
        return self.confusion_counts

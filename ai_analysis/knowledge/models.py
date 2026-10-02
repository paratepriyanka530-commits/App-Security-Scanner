"""Structured models for retrieval knowledge and vulnerability patterns."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class KnowledgeEntry(BaseModel):
    """A non-executable piece of semantic security knowledge."""

    model_config = ConfigDict(frozen=True)

    id: str
    owasp_category: str
    title: str
    description: str
    semantic_indicators: list[str] = Field(min_length=1)
    specification_evidence: list[str] = Field(min_length=1)
    limitations: list[str] = Field(min_length=1)
    example_patterns: list[str] = Field(min_length=1)

    @field_validator("id", "owasp_category", "title", "description")
    @classmethod
    def reject_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator(
        "semantic_indicators",
        "specification_evidence",
        "limitations",
        "example_patterns",
    )
    @classmethod
    def reject_empty_list_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("items must not be empty")
        return values


class APIShape(BaseModel):
    """Specification-visible shape associated with a public vulnerability case."""

    model_config = ConfigDict(frozen=True)

    methods: list[str] = Field(default_factory=list)
    path_patterns: list[str] = Field(default_factory=list)
    parameter_patterns: list[str] = Field(default_factory=list)
    request_field_patterns: list[str] = Field(default_factory=list)
    response_field_patterns: list[str] = Field(default_factory=list)

    @field_validator("methods")
    @classmethod
    def normalize_methods(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("methods must not contain empty values")
        return [value.upper() for value in values]

    @field_validator(
        "path_patterns",
        "parameter_patterns",
        "request_field_patterns",
        "response_field_patterns",
    )
    @classmethod
    def reject_empty_shape_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("API shape values must not be empty")
        return values


class VulnerabilityPattern(BaseModel):
    """Traceable, non-exploitative pattern derived from a vulnerable API project."""

    model_config = ConfigDict(frozen=True)

    pattern_id: str
    source_project: str
    source_reference: str
    title: str
    owasp_category: str
    description: str
    api_shape: APIShape = Field(default_factory=APIShape)
    semantic_context: list[str] = Field(default_factory=list)
    vulnerability_pattern: str
    security_reasoning: str
    semantic_indicators: list[str] = Field(min_length=1)
    evidence_to_compare: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(min_length=1)
    evidence_visibility: Literal[
        "SPECIFICATION_VISIBLE",
        "SEMANTIC_INFERENCE",
        "RUNTIME_REQUIRED",
        "MIXED",
    ]

    @field_validator(
        "pattern_id",
        "source_project",
        "source_reference",
        "title",
        "owasp_category",
        "description",
        "vulnerability_pattern",
        "security_reasoning",
    )
    @classmethod
    def reject_empty_critical_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("source_reference")
    @classmethod
    def validate_source_reference(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("source_reference must be an HTTP or HTTPS URL")
        return value

    @field_validator(
        "semantic_context",
        "semantic_indicators",
        "evidence_to_compare",
        "limitations",
    )
    @classmethod
    def reject_empty_pattern_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("items must not be empty")
        return values

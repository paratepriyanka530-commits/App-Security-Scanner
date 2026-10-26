"""Reproducible orchestration for endpoint-level detector experiments."""

from __future__ import annotations

import json
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from ai_analysis.context_builder import build_endpoint_context
from ai_analysis.evaluation.comparison import compare_configurations
from ai_analysis.evaluation.evaluator import (
    ai_findings_to_predictions,
    evaluate_predictions,
    static_findings_to_predictions,
    validated_findings_to_predictions,
)
from ai_analysis.evaluation.models import (
    EvaluationPrediction,
    EvaluationResult,
    GroundTruthLabel,
)
from ai_analysis.knowledge.vulnerability_patterns import VULNERABILITY_PATTERNS
from ai_analysis.llm.base import LLMProvider, LLMProviderError
from ai_analysis.llm.ollama_provider import OllamaProvider
from ai_analysis.rag.retriever import retrieve_relevant_knowledge
from ai_analysis.schemas import AIFinding
from ai_analysis.semantic_analyzer import analyze_endpoint
from ai_analysis.validation.cross_validator import cross_validate_findings
from parser.openapi_parser import parse_openapi
from scanner.scanner import scan_parsed_api


class ExperimentRunnerError(RuntimeError):
    """Base exception for experiment setup and execution failures."""


class GroundTruthValidationError(ExperimentRunnerError):
    """Raised when the supplied ground-truth corpus is invalid."""


class ExperimentParserError(ExperimentRunnerError):
    """Raised when an input OpenAPI document cannot be parsed."""


class InvalidOpenAPIError(ExperimentParserError):
    """Raised when a referenced file is not a valid supported OpenAPI document."""


class ExperimentEvaluationError(ExperimentRunnerError):
    """Raised when predictions cannot be evaluated consistently."""


class ExperimentGroundTruthRecord(GroundTruthLabel):
    """A ground-truth label associated with one OpenAPI file."""

    file: str
    vulnerable: StrictBool

    @field_validator("file")
    @classmethod
    def reject_empty_file(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class ExperimentConfig(BaseModel):
    """Configuration for one reproducible detector experiment."""

    ground_truth_path: Path
    model: str
    evaluation_directory: Path | None = None
    base_url: str = "http://localhost:11434"
    timeout: float = Field(default=120.0, gt=0)
    use_rag: bool = True
    top_k: int = Field(default=3, gt=0)
    file_filter: list[str] | None = None

    @field_validator("model", "base_url")
    @classmethod
    def reject_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("file_filter")
    @classmethod
    def validate_file_filter(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and any(not item.strip() for item in value):
            raise ValueError("file_filter entries must not be empty")
        return value


class ExperimentError(BaseModel):
    """One recoverable endpoint-analysis failure."""

    file: str
    endpoint: str
    method: str
    category: Literal["MODEL_PROVIDER", "AI_ANALYSIS"]
    message: str


class ExperimentResult(BaseModel):
    """Structured output for a complete or incomplete experiment."""

    status: Literal["COMPLETE", "INCOMPLETE"]
    model_name: str
    model_provider: str
    use_rag: bool
    top_k: int
    pattern_count: int
    file_count: int = Field(ge=0)
    endpoint_count: int = Field(ge=0)
    successful_ai_analyses: int = Field(ge=0)
    failed_ai_analyses: int = Field(ge=0)
    static_evaluation: EvaluationResult
    ai_evaluation: EvaluationResult | None = None
    hybrid_evaluation: EvaluationResult | None = None
    errors: list[ExperimentError] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_completion(self):
        if self.status == "COMPLETE":
            if self.errors or self.failed_ai_analyses:
                raise ValueError("complete experiments cannot contain AI failures")
            if self.ai_evaluation is None or self.hybrid_evaluation is None:
                raise ValueError("complete experiments require all evaluations")
        else:
            if not self.errors or not self.failed_ai_analyses:
                raise ValueError("incomplete experiments require AI failure details")
            if self.ai_evaluation is not None or self.hybrid_evaluation is not None:
                raise ValueError("incomplete AI or hybrid metrics would be misleading")
        return self


def _selected(record: ExperimentGroundTruthRecord, filters: list[str] | None) -> bool:
    if not filters:
        return True
    normalized = {item.strip() for item in filters}
    return record.file in normalized or Path(record.file).name in normalized


def load_ground_truth(
    path: str | Path,
    evaluation_directory: str | Path | None = None,
    file_filter: list[str] | None = None,
) -> list[ExperimentGroundTruthRecord]:
    """Load and validate explicitly supplied endpoint-level ground truth."""
    ground_truth_path = Path(path)
    if not ground_truth_path.is_file():
        raise GroundTruthValidationError(
            f"Ground-truth file not found: {ground_truth_path}"
        )

    try:
        payload = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise GroundTruthValidationError(
            f"Malformed ground-truth JSON: {error.msg}"
        ) from error
    except OSError as error:
        raise GroundTruthValidationError(
            f"Unable to read ground-truth file: {ground_truth_path}"
        ) from error

    if not isinstance(payload, list):
        raise GroundTruthValidationError("Ground truth must be a JSON array")

    try:
        records = [ExperimentGroundTruthRecord.model_validate(item) for item in payload]
    except ValidationError as error:
        raise GroundTruthValidationError(f"Invalid ground-truth record: {error}") from error

    records = [record for record in records if _selected(record, file_filter)]
    if not records:
        raise GroundTruthValidationError("No ground-truth records matched the selection")

    base_directory = (
        Path(evaluation_directory)
        if evaluation_directory is not None
        else ground_truth_path.parent
    )
    for record in records:
        referenced_file = Path(record.file)
        if not referenced_file.is_absolute():
            referenced_file = base_directory / referenced_file
        if not referenced_file.is_file():
            raise GroundTruthValidationError(
                f"Referenced OpenAPI file not found: {record.file}"
            )

    return records


def _resolved_file(record: ExperimentGroundTruthRecord, base: Path) -> Path:
    path = Path(record.file)
    return path if path.is_absolute() else base / path


def _namespaced_endpoint(file_id: str, endpoint: str) -> str:
    # Evaluation keys otherwise merge identical paths from different API files.
    return f"{file_id}::{endpoint}"


def _namespace_predictions(
    predictions: list[EvaluationPrediction], file_id: str
) -> list[EvaluationPrediction]:
    return [
        prediction.model_copy(
            update={
                "endpoint": _namespaced_endpoint(file_id, prediction.endpoint),
            }
        )
        for prediction in predictions
    ]


def _validate_label_coverage(
    records: list[ExperimentGroundTruthRecord], endpoints: list[dict], file_id: str
) -> None:
    parsed_keys = {(item["path"], item["method"].upper()) for item in endpoints}
    label_keys = {(item.endpoint, item.method) for item in records}
    unknown = label_keys - parsed_keys
    missing = parsed_keys - label_keys
    if unknown:
        endpoint, method = sorted(unknown)[0]
        raise GroundTruthValidationError(
            f"Ground truth references unknown endpoint in {file_id}: {method} {endpoint}"
        )
    if missing:
        endpoint, method = sorted(missing)[0]
        raise GroundTruthValidationError(
            f"Ground truth is missing endpoint label in {file_id}: {method} {endpoint}"
        )


def run_experiment(
    config: ExperimentConfig,
    provider: LLMProvider | None = None,
) -> ExperimentResult:
    """Run static, AI, and hybrid configurations over a labeled corpus."""
    if not isinstance(config, ExperimentConfig):
        config = ExperimentConfig.model_validate(config)
    if provider is not None and not isinstance(provider, LLMProvider):
        raise TypeError("provider must implement LLMProvider")

    records = load_ground_truth(
        config.ground_truth_path,
        config.evaluation_directory,
        config.file_filter,
    )
    base = config.evaluation_directory or config.ground_truth_path.parent
    grouped: dict[Path, list[ExperimentGroundTruthRecord]] = defaultdict(list)
    for record in records:
        grouped[_resolved_file(record, base)].append(record)

    active_provider = provider or OllamaProvider(
        model=config.model,
        base_url=config.base_url,
        timeout=config.timeout,
    )
    retriever = (
        partial(retrieve_relevant_knowledge, top_k=config.top_k)
        if config.use_rag
        else None
    )

    labels: list[GroundTruthLabel] = []
    static_predictions: list[EvaluationPrediction] = []
    ai_predictions: list[EvaluationPrediction] = []
    hybrid_predictions: list[EvaluationPrediction] = []
    errors: list[ExperimentError] = []
    endpoint_count = 0
    successes = 0

    for spec_path, file_records in grouped.items():
        file_id = file_records[0].file
        try:
            parsed = parse_openapi(str(spec_path))
        except ValueError as error:
            raise InvalidOpenAPIError(
                f"Invalid OpenAPI file {file_id}: {error}"
            ) from error
        except Exception as error:
            raise ExperimentParserError(
                f"Unable to parse OpenAPI file {file_id}: {error}"
            ) from error

        endpoints = parsed.get("endpoints", [])
        _validate_label_coverage(file_records, endpoints, file_id)
        endpoint_count += len(endpoints)
        labels.extend(
            GroundTruthLabel(
                endpoint=_namespaced_endpoint(file_id, record.endpoint),
                method=record.method,
                owasp_category=record.owasp_category,
                vulnerable=record.vulnerable,
            )
            for record in file_records
        )

        scan_result = scan_parsed_api(parsed, source=spec_path)
        static_findings = scan_result["findings"]
        static_predictions.extend(
            _namespace_predictions(
                static_findings_to_predictions(static_findings), file_id
            )
        )

        ai_findings: list[AIFinding] = []
        file_failed = False
        for endpoint in endpoints:
            context = build_endpoint_context(
                endpoint,
                parsed.get("api_info"),
                parsed.get("security_schemes"),
            )
            try:
                result = analyze_endpoint(context, active_provider, retriever=retriever)
            except Exception as error:
                file_failed = True
                errors.append(
                    ExperimentError(
                        file=file_id,
                        endpoint=endpoint["path"],
                        method=endpoint["method"],
                        category=(
                            "MODEL_PROVIDER"
                            if isinstance(error, LLMProviderError)
                            else "AI_ANALYSIS"
                        ),
                        message=str(error),
                    )
                )
                continue

            successes += 1
            ai_findings.extend(result.findings)
            ai_predictions.extend(
                _namespace_predictions(
                    ai_findings_to_predictions(result.findings), file_id
                )
            )

        # Do not form a partial hybrid result for a file with failed AI analyses.
        if not file_failed:
            validated = cross_validate_findings(static_findings, ai_findings)
            hybrid_predictions.extend(
                _namespace_predictions(
                    validated_findings_to_predictions(validated), file_id
                )
            )

    try:
        static_evaluation = evaluate_predictions(labels, static_predictions)
        if errors:
            ai_evaluation = None
            hybrid_evaluation = None
        else:
            comparison = compare_configurations(
                labels,
                static_predictions,
                ai_predictions,
                hybrid_predictions,
            )
            ai_evaluation = comparison["AI"]
            hybrid_evaluation = comparison["HYBRID"]
    except Exception as error:
        raise ExperimentEvaluationError(f"Unable to evaluate predictions: {error}") from error

    return ExperimentResult(
        status="INCOMPLETE" if errors else "COMPLETE",
        model_name=config.model,
        model_provider="Ollama",
        use_rag=config.use_rag,
        top_k=config.top_k,
        pattern_count=len(VULNERABILITY_PATTERNS),
        file_count=len(grouped),
        endpoint_count=endpoint_count,
        successful_ai_analyses=successes,
        failed_ai_analyses=len(errors),
        static_evaluation=static_evaluation,
        ai_evaluation=ai_evaluation,
        hybrid_evaluation=hybrid_evaluation,
        errors=errors,
    )

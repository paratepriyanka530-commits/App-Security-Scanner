"""Evaluate already-produced findings against endpoint-level ground truth."""

from collections.abc import Mapping
from typing import Any

from ai_analysis.evaluation.matcher import endpoint_key, evaluation_key
from ai_analysis.evaluation.metrics import (
    accuracy,
    f1_score,
    false_positive_rate,
    precision,
    recall,
)
from ai_analysis.evaluation.models import (
    ConfusionCounts,
    EvaluationPrediction,
    EvaluationResult,
    GroundTruthLabel,
)
from ai_analysis.schemas import AIFinding, AIAnalysisResult
from ai_analysis.validation.models import ValidatedFinding


def _field(item: Any, name: str) -> Any:
    if isinstance(item, Mapping):
        return item.get(name)
    return getattr(item, name, None)


def static_findings_to_predictions(
    findings: list[dict],
) -> list[EvaluationPrediction]:
    """Adapt existing scanner finding dictionaries without using severity."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")
    return [
        EvaluationPrediction(
            endpoint=_field(finding, "endpoint"),
            method=_field(finding, "method"),
            owasp_category=_field(finding, "owasp_category"),
            detected=True,
            confidence=_field(finding, "confidence"),
            source="STATIC",
        )
        for finding in findings
    ]


def ai_findings_to_predictions(
    findings: list[AIFinding],
) -> list[EvaluationPrediction]:
    """Adapt existing AI finding objects into evaluation predictions."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    validated = [
        finding
        if isinstance(finding, AIFinding)
        else AIFinding.model_validate(finding)
        for finding in findings
    ]
    return [
        EvaluationPrediction(
            endpoint=finding.endpoint,
            method=finding.method,
            owasp_category=finding.owasp_category,
            detected=True,
            confidence=finding.confidence,
            source="AI",
        )
        for finding in validated
    ]


def ai_result_to_predictions(
    result: AIAnalysisResult,
) -> list[EvaluationPrediction]:
    """Adapt the findings of one validated AI analysis result."""
    if not isinstance(result, AIAnalysisResult):
        raise TypeError("result must be an AIAnalysisResult")
    return ai_findings_to_predictions(result.findings)


def validated_findings_to_predictions(
    findings: list[ValidatedFinding],
) -> list[EvaluationPrediction]:
    """Adapt every retained hybrid finding, including MANUAL_REVIEW."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    validated = [
        finding
        if isinstance(finding, ValidatedFinding)
        else ValidatedFinding.model_validate(finding)
        for finding in findings
    ]
    return [
        EvaluationPrediction(
            endpoint=finding.endpoint,
            method=finding.method,
            owasp_category=finding.owasp_category,
            detected=True,
            confidence=finding.confidence,
            source="HYBRID",
        )
        for finding in validated
    ]


def evaluate_predictions(
    ground_truth: list[GroundTruthLabel],
    predictions: list[EvaluationPrediction],
) -> EvaluationResult:
    """Evaluate unique endpoint/method/category predictions deterministically."""
    if not isinstance(ground_truth, list):
        raise TypeError("ground_truth must be a list")
    if not isinstance(predictions, list):
        raise TypeError("predictions must be a list")

    labels = [
        label
        if isinstance(label, GroundTruthLabel)
        else GroundTruthLabel.model_validate(label)
        for label in ground_truth
    ]
    evaluated_predictions = [
        prediction
        if isinstance(prediction, EvaluationPrediction)
        else EvaluationPrediction.model_validate(prediction)
        for prediction in predictions
    ]

    positive_keys = {
        evaluation_key(label.endpoint, label.method, label.owasp_category)
        for label in labels
        if label.vulnerable
    }
    safe_keys = {
        endpoint_key(label.endpoint, label.method)
        for label in labels
        if not label.vulnerable
    }
    vulnerable_endpoint_keys = {key[:2] for key in positive_keys}
    conflicting_keys = safe_keys & vulnerable_endpoint_keys
    if conflicting_keys:
        raise ValueError(
            "ground truth cannot mark the same endpoint and method as both safe and vulnerable"
        )

    prediction_keys = {
        evaluation_key(
            prediction.endpoint,
            prediction.method,
            prediction.owasp_category,
        )
        for prediction in evaluated_predictions
        if prediction.detected
    }

    true_positive = len(positive_keys & prediction_keys)
    false_negative = len(positive_keys - prediction_keys)
    false_positive = len(prediction_keys - positive_keys)
    predicted_endpoint_keys = {key[:2] for key in prediction_keys}
    true_negative = len(safe_keys - predicted_endpoint_keys)

    counts = ConfusionCounts(
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        true_negative=true_negative,
    )
    return EvaluationResult(
        confusion_counts=counts,
        precision=precision(counts),
        recall=recall(counts),
        f1_score=f1_score(counts),
        false_positive_rate=false_positive_rate(counts),
        accuracy=accuracy(counts),
    )

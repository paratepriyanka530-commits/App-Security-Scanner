"""Compare measured results without ranking detector configurations."""

from ai_analysis.evaluation.evaluator import evaluate_predictions
from ai_analysis.evaluation.models import (
    EvaluationPrediction,
    EvaluationResult,
    GroundTruthLabel,
)


def compare_configurations(
    ground_truth: list[GroundTruthLabel],
    static_predictions: list[EvaluationPrediction],
    ai_predictions: list[EvaluationPrediction],
    hybrid_predictions: list[EvaluationPrediction],
) -> dict[str, EvaluationResult]:
    """Return independent metrics for STATIC, AI, and HYBRID inputs."""
    return {
        "STATIC": evaluate_predictions(ground_truth, static_predictions),
        "AI": evaluate_predictions(ground_truth, ai_predictions),
        "HYBRID": evaluate_predictions(ground_truth, hybrid_predictions),
    }

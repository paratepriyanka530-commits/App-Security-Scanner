"""Endpoint-level evaluation for static, AI, and hybrid predictions."""

from ai_analysis.evaluation.comparison import compare_configurations
from ai_analysis.evaluation.evaluator import (
    ai_findings_to_predictions,
    ai_result_to_predictions,
    evaluate_predictions,
    static_findings_to_predictions,
    validated_findings_to_predictions,
)
from ai_analysis.evaluation.models import (
    ConfusionCounts,
    EvaluationPrediction,
    EvaluationResult,
    GroundTruthLabel,
)
from ai_analysis.evaluation.experiment_runner import (
    ExperimentConfig,
    ExperimentError,
    ExperimentEvaluationError,
    ExperimentGroundTruthRecord,
    ExperimentParserError,
    ExperimentResult,
    ExperimentRunnerError,
    GroundTruthValidationError,
    InvalidOpenAPIError,
    load_ground_truth,
    run_experiment,
)

__all__ = [
    "ConfusionCounts",
    "EvaluationPrediction",
    "EvaluationResult",
    "GroundTruthLabel",
    "ExperimentConfig",
    "ExperimentError",
    "ExperimentEvaluationError",
    "ExperimentGroundTruthRecord",
    "ExperimentParserError",
    "ExperimentResult",
    "ExperimentRunnerError",
    "GroundTruthValidationError",
    "InvalidOpenAPIError",
    "ai_findings_to_predictions",
    "ai_result_to_predictions",
    "compare_configurations",
    "evaluate_predictions",
    "load_ground_truth",
    "run_experiment",
    "static_findings_to_predictions",
    "validated_findings_to_predictions",
]

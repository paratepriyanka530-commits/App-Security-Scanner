"""Pure classification metric calculations."""

from ai_analysis.evaluation.models import ConfusionCounts


def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def precision(counts: ConfusionCounts) -> float:
    return _safe_ratio(
        counts.true_positive,
        counts.true_positive + counts.false_positive,
    )


def recall(counts: ConfusionCounts) -> float:
    return _safe_ratio(
        counts.true_positive,
        counts.true_positive + counts.false_negative,
    )


def f1_score(counts: ConfusionCounts) -> float:
    precision_value = precision(counts)
    recall_value = recall(counts)
    return _safe_ratio(
        2 * precision_value * recall_value,
        precision_value + recall_value,
    )


def false_positive_rate(counts: ConfusionCounts) -> float:
    return _safe_ratio(
        counts.false_positive,
        counts.false_positive + counts.true_negative,
    )


def accuracy(counts: ConfusionCounts) -> float:
    total = (
        counts.true_positive
        + counts.false_positive
        + counts.false_negative
        + counts.true_negative
    )
    return _safe_ratio(counts.true_positive + counts.true_negative, total)

from copy import deepcopy

import pytest
from pydantic import ValidationError

from ai_analysis.evaluation.comparison import compare_configurations
from ai_analysis.evaluation.evaluator import (
    ai_findings_to_predictions,
    ai_result_to_predictions,
    evaluate_predictions,
    static_findings_to_predictions,
    validated_findings_to_predictions,
)
from ai_analysis.evaluation.matcher import prediction_matches_label
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
    GroundTruthLabel,
)
from ai_analysis.schemas import AIFinding, AIAnalysisResult
from ai_analysis.validation.models import ValidatedFinding


def truth(endpoint, method, category=None, vulnerable=True):
    return GroundTruthLabel(
        endpoint=endpoint,
        method=method,
        owasp_category=category,
        vulnerable=vulnerable,
    )


def prediction(endpoint, method, category, source=None):
    return EvaluationPrediction(
        endpoint=endpoint,
        method=method,
        owasp_category=category,
        detected=True,
        source=source,
    )


API1 = "API1:2023 Broken Object Level Authorization"
API3 = "API3:2023 Broken Object Property Level Authorization"
API6 = "API6:2023 Unrestricted Access to Sensitive Business Flows"
API8 = "API8:2023 Security Misconfiguration"


def test_ground_truth_requires_category_only_for_vulnerable_labels():
    with pytest.raises(ValidationError):
        truth("/users", "GET", category=None, vulnerable=True)
    with pytest.raises(ValidationError):
        truth("/health", "GET", category=API8, vulnerable=False)

    safe = truth("/health", "get", category=None, vulnerable=False)
    assert safe.method == "GET"
    assert safe.owasp_category is None


def test_perfect_detection_metrics():
    result = evaluate_predictions(
        [
            truth("/users/{id}", "GET", API1),
            truth("/health", "GET", vulnerable=False),
        ],
        [prediction("/users/{id}", "GET", API1)],
    )

    assert result.confusion_counts == ConfusionCounts(
        true_positive=1,
        false_positive=0,
        false_negative=0,
        true_negative=1,
    )
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1_score == 1.0
    assert result.false_positive_rate == 0.0
    assert result.accuracy == 1.0


def test_all_missed_vulnerabilities():
    result = evaluate_predictions(
        [truth("/users/{id}", "GET", API1)],
        [],
    )

    assert result.confusion_counts.false_negative == 1
    assert result.confusion_counts.true_negative == 0
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1_score == 0.0


def test_all_false_alarms_on_safe_endpoint():
    result = evaluate_predictions(
        [truth("/health", "GET", vulnerable=False)],
        [prediction("/health", "GET", API8)],
    )

    assert result.confusion_counts == ConfusionCounts(
        true_positive=0,
        false_positive=1,
        false_negative=0,
        true_negative=0,
    )
    assert result.false_positive_rate == 1.0


def test_zero_denominators_return_zero():
    counts = ConfusionCounts(
        true_positive=0,
        false_positive=0,
        false_negative=0,
        true_negative=0,
    )

    assert precision(counts) == 0.0
    assert recall(counts) == 0.0
    assert f1_score(counts) == 0.0
    assert false_positive_rate(counts) == 0.0
    assert accuracy(counts) == 0.0


@pytest.mark.parametrize(
    "counts",
    [
        ConfusionCounts(
            true_positive=2,
            false_positive=1,
            false_negative=3,
            true_negative=4,
        ),
        ConfusionCounts(
            true_positive=0,
            false_positive=5,
            false_negative=0,
            true_negative=2,
        ),
    ],
)
def test_all_metric_values_remain_between_zero_and_one(counts):
    values = [
        precision(counts),
        recall(counts),
        f1_score(counts),
        false_positive_rate(counts),
        accuracy(counts),
    ]
    assert all(0.0 <= value <= 1.0 for value in values)


def test_correct_complete_evaluation_unit_is_true_positive():
    result = evaluate_predictions(
        [truth("/users/{id}", "GET", API1)],
        [prediction("/users/{id}", "GET", API1)],
    )

    assert result.confusion_counts.true_positive == 1
    assert result.confusion_counts.false_positive == 0
    assert result.confusion_counts.false_negative == 0


@pytest.mark.parametrize(
    "wrong_prediction",
    [
        prediction("/users/{id}", "GET", API3),
        prediction("/accounts/{id}", "GET", API1),
        prediction("/users/{id}", "POST", API1),
    ],
)
def test_wrong_category_endpoint_or_method_is_false_positive_and_false_negative(
    wrong_prediction,
):
    result = evaluate_predictions(
        [truth("/users/{id}", "GET", API1)],
        [wrong_prediction],
    )

    assert result.confusion_counts.false_positive == 1
    assert result.confusion_counts.false_negative == 1
    assert result.confusion_counts.true_positive == 0


def test_method_case_and_owasp_label_forms_are_normalized():
    assert prediction_matches_label(
        "/users/{id}",
        "get",
        "API1",
        "/users/{id}",
        "GET",
        API1,
    )
    result = evaluate_predictions(
        [truth("/users/{id}", "get", API1)],
        [prediction("/users/{id}", "GET", "API1 Broken Object Level Authorization")],
    )
    assert result.confusion_counts.true_positive == 1


def test_safe_endpoint_without_prediction_is_true_negative():
    result = evaluate_predictions(
        [truth("/health", "GET", vulnerable=False)],
        [],
    )

    assert result.confusion_counts.true_negative == 1
    assert result.confusion_counts.false_positive == 0


def test_duplicate_identical_predictions_count_once():
    duplicate = prediction("/users/{id}", "GET", API1)

    result = evaluate_predictions(
        [truth("/users/{id}", "GET", API1)],
        [duplicate, duplicate.model_copy(deep=True)],
    )

    assert result.confusion_counts.true_positive == 1
    assert result.confusion_counts.false_positive == 0


def test_multi_label_endpoint_counts_one_detected_and_one_missed():
    result = evaluate_predictions(
        [
            truth("/admin/import", "POST", "API5"),
            truth("/admin/import", "POST", "API10"),
        ],
        [prediction("/admin/import", "POST", "API5")],
    )

    assert result.confusion_counts.true_positive == 1
    assert result.confusion_counts.false_negative == 1
    assert result.confusion_counts.false_positive == 0


def test_static_findings_adapter_ignores_severity_for_evaluation():
    predictions = static_findings_to_predictions(
        [
            {
                "finding_id": "F-001-01",
                "endpoint": "/users",
                "method": "get",
                "rule": "Sensitive Data Exposure",
                "owasp_category": API3,
                "severity": "INFO",
                "confidence": 0.85,
                "evidence": "Password response property.",
            }
        ]
    )

    assert predictions == [
        EvaluationPrediction(
            endpoint="/users",
            method="GET",
            owasp_category=API3,
            detected=True,
            confidence=0.85,
            source="STATIC",
        )
    ]


def test_ai_result_adapter_converts_findings():
    finding = AIFinding(
        endpoint="/users",
        method="GET",
        rule="Sensitive response property",
        owasp_category=API3,
        severity="HIGH",
        confidence=0.8,
        evidence="Password is documented in the response schema.",
    )
    result = AIAnalysisResult(
        endpoint="/users",
        method="GET",
        status="POTENTIAL_VULNERABILITY",
        findings=[finding],
    )

    predictions = ai_result_to_predictions(result)

    assert len(predictions) == 1
    assert predictions[0].owasp_category == API3
    assert predictions[0].source == "AI"
    assert ai_findings_to_predictions([finding]) == predictions


def test_hybrid_adapter_retains_manual_review_as_prediction():
    finding = ValidatedFinding(
        endpoint="/coupon",
        method="POST",
        vulnerability="Potential coupon flow abuse",
        owasp_category=API6,
        severity="MEDIUM",
        confidence=0.7,
        detected_by="AI",
        validation_status="MANUAL_REVIEW",
        ai_evidence="Coupon redemption can be automated.",
        ai_rule="Sensitive business flow",
        ai_confidence=0.7,
    )

    predictions = validated_findings_to_predictions([finding])

    assert len(predictions) == 1
    assert predictions[0].detected is True
    assert predictions[0].source == "HYBRID"


def test_configuration_comparison_keeps_results_separate_with_expected_counts():
    ground_truth = [
        truth("/users/{id}", "GET", API1),
        truth("/health", "GET", vulnerable=False),
        truth("/coupon", "POST", API6),
    ]
    static_predictions = [prediction("/users/{id}", "GET", API1)]
    ai_predictions = [
        prediction("/users/{id}", "GET", API1),
        prediction("/coupon", "POST", API6),
        prediction("/health", "GET", API8),
    ]
    hybrid_predictions = [
        prediction("/users/{id}", "GET", API1),
        prediction("/coupon", "POST", API6),
    ]

    comparison = compare_configurations(
        ground_truth,
        static_predictions,
        ai_predictions,
        hybrid_predictions,
    )

    assert set(comparison) == {"STATIC", "AI", "HYBRID"}
    assert comparison["STATIC"].confusion_counts == ConfusionCounts(
        true_positive=1,
        false_positive=0,
        false_negative=1,
        true_negative=1,
    )
    assert comparison["AI"].confusion_counts == ConfusionCounts(
        true_positive=2,
        false_positive=1,
        false_negative=0,
        true_negative=0,
    )
    assert comparison["HYBRID"].confusion_counts == ConfusionCounts(
        true_positive=2,
        false_positive=0,
        false_negative=0,
        true_negative=1,
    )
    assert comparison["STATIC"].precision == 1.0
    assert comparison["STATIC"].recall == 0.5
    assert comparison["AI"].precision == pytest.approx(2 / 3)
    assert comparison["AI"].recall == 1.0
    assert comparison["HYBRID"].f1_score == 1.0


def test_evaluation_does_not_mutate_inputs():
    ground_truth = [truth("/users/{id}", "GET", API1)]
    predictions = [prediction("/users/{id}", "GET", API1)]
    original_truth = deepcopy(ground_truth)
    original_predictions = deepcopy(predictions)

    evaluate_predictions(ground_truth, predictions)

    assert ground_truth == original_truth
    assert predictions == original_predictions


def test_conflicting_safe_and_vulnerable_ground_truth_fails_clearly():
    with pytest.raises(ValueError, match="both safe and vulnerable"):
        evaluate_predictions(
            [
                truth("/users", "GET", API1),
                truth("/users", "GET", vulnerable=False),
            ],
            [],
        )

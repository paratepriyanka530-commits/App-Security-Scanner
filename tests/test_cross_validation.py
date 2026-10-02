import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_analysis.context_builder import build_endpoint_context
from ai_analysis.llm.mock_provider import MockLLMProvider
from ai_analysis.schemas import AIFinding
from ai_analysis.semantic_analyzer import analyze_endpoint
from ai_analysis.validation.cross_validator import cross_validate_findings
from ai_analysis.validation.matcher import findings_match, normalize_owasp_category
from parser.openapi_parser import parse_openapi
from scanner.scanner import scan_parsed_api


STATIC_FINDING = {
    "finding_id": "F-001-01",
    "endpoint": "/users",
    "method": "GET",
    "rule": "Sensitive Data Exposure",
    "owasp_category": "API3:2023 Broken Object Property Level Authorization",
    "severity": "HIGH",
    "confidence": 0.85,
    "evidence": "Sensitive field 'password' may be exposed in a response.",
}

AI_FINDING = AIFinding(
    endpoint="/users",
    method="GET",
    rule="Find sensitive properties in the response",
    owasp_category="API3:2023 Broken Object Property Level Authorization",
    severity="MEDIUM",
    confidence=0.75,
    evidence="The response schema contains a password property.",
)


def test_same_category_with_different_rule_names_matches():
    assert findings_match(STATIC_FINDING, AI_FINDING)


def test_full_api3_label_matches_short_api3_label():
    short_category = AI_FINDING.model_copy(update={"owasp_category": "API3"})

    assert findings_match(STATIC_FINDING, short_category)
    assert normalize_owasp_category("API3 Broken Object Property Level Authorization") == "API3"


@pytest.mark.parametrize(
    "changed_finding",
    [
        AI_FINDING.model_copy(update={"endpoint": "/accounts"}),
        AI_FINDING.model_copy(update={"method": "POST"}),
        AI_FINDING.model_copy(update={"owasp_category": "API8:2023 Security Misconfiguration"}),
    ],
)
def test_different_endpoint_method_or_category_does_not_match(changed_finding):
    assert not findings_match(STATIC_FINDING, changed_finding)


def test_matching_findings_produce_confirmed_both_result():
    result = cross_validate_findings([STATIC_FINDING], [AI_FINDING])[0]

    assert result.detected_by == "BOTH"
    assert result.validation_status == "CONFIRMED"
    assert result.static_rule == "Sensitive Data Exposure"
    assert result.ai_rule == "Find sensitive properties in the response"


def test_static_only_finding_is_retained():
    result = cross_validate_findings([STATIC_FINDING], [])[0]

    assert result.detected_by == "STATIC"
    assert result.validation_status == "RETAINED"
    assert result.confidence == 0.85
    assert result.static_evidence == STATIC_FINDING["evidence"]
    assert result.ai_evidence is None


def test_ai_only_finding_requires_manual_review():
    result = cross_validate_findings([], [AI_FINDING])[0]

    assert result.detected_by == "AI"
    assert result.validation_status == "MANUAL_REVIEW"
    assert result.confidence == 0.75
    assert result.ai_evidence == AI_FINDING.evidence
    assert result.static_evidence is None


def test_combined_confidence_uses_independent_confirmation_formula():
    result = cross_validate_findings([STATIC_FINDING], [AI_FINDING])[0]

    expected = 1 - ((1 - 0.85) * (1 - 0.75))
    assert result.confidence == pytest.approx(expected)
    assert result.confidence > STATIC_FINDING["confidence"]
    assert result.confidence > AI_FINDING.confidence
    assert result.confidence <= 1.0


def test_combined_confidence_never_exceeds_one():
    static = {**STATIC_FINDING, "confidence": 1.0}
    ai = AI_FINDING.model_copy(update={"confidence": 1.0})

    assert cross_validate_findings([static], [ai])[0].confidence == 1.0


def test_higher_severity_wins_without_averaging():
    static = {**STATIC_FINDING, "severity": "LOW"}
    ai = AI_FINDING.model_copy(update={"severity": "CRITICAL"})

    assert cross_validate_findings([static], [ai])[0].severity == "CRITICAL"


def test_confirmed_result_preserves_both_evidence_fields():
    result = cross_validate_findings([STATIC_FINDING], [AI_FINDING])[0]

    assert result.static_evidence == STATIC_FINDING["evidence"]
    assert result.ai_evidence == AI_FINDING.evidence


def test_multiple_independent_categories_remain_separate():
    api2_static = {
        **STATIC_FINDING,
        "finding_id": "F-001-02",
        "rule": "Missing Authentication",
        "owasp_category": "API2:2023 Broken Authentication",
    }

    results = cross_validate_findings(
        [STATIC_FINDING, api2_static],
        [AI_FINDING],
    )

    assert len(results) == 2
    assert [result.detected_by for result in results] == ["BOTH", "STATIC"]
    assert len({result.owasp_category for result in results}) == 2


def test_repeated_category_findings_are_paired_one_to_one():
    second_static = {
        **STATIC_FINDING,
        "finding_id": "F-001-02",
        "rule": "Second static observation",
        "evidence": "A separate piece of static evidence.",
    }
    second_ai = AI_FINDING.model_copy(
        update={
            "rule": "Second AI observation",
            "evidence": "A separate piece of AI evidence.",
        }
    )

    results = cross_validate_findings(
        [STATIC_FINDING, second_static],
        [AI_FINDING, second_ai],
    )

    assert len(results) == 2
    assert all(result.detected_by == "BOTH" for result in results)
    assert results[0].ai_rule == AI_FINDING.rule
    assert results[1].ai_rule == second_ai.rule


def test_empty_inputs_return_empty_list():
    assert cross_validate_findings([], []) == []


def test_inputs_are_not_mutated():
    static_findings = [deepcopy(STATIC_FINDING)]
    ai_findings = [AI_FINDING.model_copy(deep=True)]
    original_static = deepcopy(static_findings)
    original_ai = [finding.model_copy(deep=True) for finding in ai_findings]

    cross_validate_findings(static_findings, ai_findings)

    assert static_findings == original_static
    assert ai_findings == original_ai


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_invalid_static_confidence_fails_clearly(confidence):
    with pytest.raises(ValidationError):
        cross_validate_findings(
            [{**STATIC_FINDING, "confidence": confidence}],
            [],
        )


def test_parser_scanner_mock_ai_cross_validation_integration():
    sample_path = Path(__file__).parents[1] / "sample_apis" / "vulnerable_api.yaml"
    parsed = parse_openapi(str(sample_path))
    static_result = scan_parsed_api(parsed, source=sample_path)
    endpoint = next(item for item in parsed["endpoints"] if item["path"] == "/users")
    context = build_endpoint_context(
        endpoint,
        parsed["api_info"],
        parsed["security_schemes"],
    )
    provider = MockLLMProvider(
        json.dumps(
            {
                "endpoint": "/users",
                "method": "GET",
                "status": "POTENTIAL_VULNERABILITY",
                "findings": [AI_FINDING.model_dump()],
            }
        )
    )

    ai_result = analyze_endpoint(context, provider)
    validated = cross_validate_findings(
        static_result["findings"],
        ai_result.findings,
    )

    shared_api3 = [
        finding
        for finding in validated
        if finding.owasp_category.startswith("API3:")
    ]
    assert len(shared_api3) == 1
    assert shared_api3[0].detected_by == "BOTH"
    assert shared_api3[0].validation_status == "CONFIRMED"

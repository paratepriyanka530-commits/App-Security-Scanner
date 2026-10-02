from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_analysis.context_builder import build_endpoint_context
from ai_analysis.schemas import AIFinding, AIAnalysisResult
from parser.openapi_parser import parse_openapi


SAMPLE_FINDING = {
    "endpoint": "/users/{userId}",
    "method": "get",
    "rule": "Authorization semantics need review",
    "owasp_category": "API1:2023 Broken Object Level Authorization",
    "severity": "HIGH",
    "confidence": 0.85,
    "evidence": "The operation accesses a user-selected resource.",
}

SAMPLE_ENDPOINT = {
    "path": "/users/{userId}",
    "method": "get",
    "summary": "Get a user",
    "description": "Returns one user.",
    "parameters": [
        {
            "name": "userId",
            "location": "path",
            "required": True,
            "type": "string",
        }
    ],
    "request_body": None,
    "responses": [{"status_code": "200", "description": "Success"}],
    "security": [{"bearerAuth": []}],
    "rate_limit": "100/minute",
    "required_security_headers": ["X-Request-ID"],
    "required_roles": ["admin"],
}


def test_ai_finding_accepts_valid_finding():
    finding = AIFinding(**SAMPLE_FINDING)

    assert finding.endpoint == "/users/{userId}"
    assert finding.detected_by == "AI"


def test_ai_finding_normalizes_method_to_uppercase():
    finding = AIFinding(**SAMPLE_FINDING)

    assert finding.method == "GET"


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_ai_finding_rejects_out_of_range_confidence(confidence):
    with pytest.raises(ValidationError):
        AIFinding(**{**SAMPLE_FINDING, "confidence": confidence})


def test_ai_finding_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        AIFinding(**{**SAMPLE_FINDING, "severity": "URGENT"})


def test_ai_finding_rejects_empty_evidence():
    with pytest.raises(ValidationError):
        AIFinding(**{**SAMPLE_FINDING, "evidence": "   "})


def test_safe_ai_analysis_result_accepts_empty_findings():
    result = AIAnalysisResult(
        endpoint="/health", method="GET", status="SAFE", findings=[]
    )

    assert result.findings == []


def test_potential_vulnerability_result_accepts_findings():
    finding = AIFinding(**SAMPLE_FINDING)
    result = AIAnalysisResult(
        endpoint="/users/{userId}",
        method="GET",
        status="POTENTIAL_VULNERABILITY",
        findings=[finding],
    )

    assert result.findings == [finding]


def test_ai_analysis_result_normalizes_method_to_uppercase():
    result = AIAnalysisResult(endpoint="/health", method="get", status="SAFE")

    assert result.method == "GET"


def test_build_endpoint_context_returns_expected_structure():
    context = build_endpoint_context(SAMPLE_ENDPOINT)

    assert context == {
        "api": {},
        "endpoint": {
            "path": "/users/{userId}",
            "method": "GET",
            "summary": "Get a user",
            "description": "Returns one user.",
        },
        "security": {
            "requirements": [{"bearerAuth": []}],
            "security_schemes": {},
            "required_roles": ["admin"],
            "rate_limit": "100/minute",
            "required_security_headers": ["X-Request-ID"],
        },
        "parameters": SAMPLE_ENDPOINT["parameters"],
        "request_body": None,
        "responses": SAMPLE_ENDPOINT["responses"],
    }


def test_build_endpoint_context_does_not_mutate_or_share_input_data():
    endpoint = deepcopy(SAMPLE_ENDPOINT)
    original = deepcopy(endpoint)
    context = build_endpoint_context(endpoint)

    context["parameters"][0]["name"] = "changed"
    context["security"]["requirements"][0]["bearerAuth"].append("scope")

    assert endpoint == original


def test_build_endpoint_context_rejects_non_dictionary_endpoint():
    with pytest.raises(TypeError):
        build_endpoint_context([])


def test_build_endpoint_context_rejects_missing_path():
    endpoint = {key: value for key, value in SAMPLE_ENDPOINT.items() if key != "path"}

    with pytest.raises(ValueError):
        build_endpoint_context(endpoint)


def test_build_endpoint_context_rejects_missing_method():
    endpoint = {
        key: value for key, value in SAMPLE_ENDPOINT.items() if key != "method"
    }

    with pytest.raises(ValueError):
        build_endpoint_context(endpoint)


def test_build_endpoint_context_carries_api_and_security_information():
    api_info = {"title": "Student API", "version": "1.0.0"}
    security_schemes = {
        "bearerAuth": {"type": "http", "scheme": "bearer"}
    }
    context = build_endpoint_context(SAMPLE_ENDPOINT, api_info, security_schemes)

    assert context["api"] == api_info
    assert context["security"]["security_schemes"] == security_schemes
    assert context["api"] is not api_info
    assert context["security"]["security_schemes"] is not security_schemes


def test_parser_output_builds_valid_endpoint_context():
    sample_path = Path(__file__).parents[1] / "sample_apis" / "sample_api.json"
    parsed = parse_openapi(str(sample_path))

    context = build_endpoint_context(
        parsed["endpoints"][0],
        parsed["api_info"],
        parsed["security_schemes"],
    )

    assert context["endpoint"]["path"].startswith("/")
    assert context["endpoint"]["method"]
    assert context["api"] == parsed["api_info"]
    assert context["security"]["security_schemes"] == parsed["security_schemes"]

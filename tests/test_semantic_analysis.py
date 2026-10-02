import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_analysis.context_builder import build_endpoint_context
from ai_analysis.llm.mock_provider import MockLLMProvider
from ai_analysis.prompts import build_security_analysis_prompt
from ai_analysis.response_parser import parse_ai_response
from ai_analysis.schemas import AIAnalysisResult
from ai_analysis.semantic_analyzer import analyze_endpoint
from parser.openapi_parser import parse_openapi


CONTEXT = {
    "api": {"title": "Accounts API", "version": "1.0"},
    "endpoint": {
        "path": "/accounts/{accountId}",
        "method": "GET",
        "summary": "Get an account",
        "description": "Returns account details.",
    },
    "security": {
        "requirements": [{"bearerAuth": []}],
        "security_schemes": {"bearerAuth": {"type": "http"}},
        "required_roles": ["account-reader"],
        "rate_limit": None,
        "required_security_headers": [],
    },
    "parameters": [
        {
            "name": "accountId",
            "location": "path",
            "required": True,
            "type": "string",
        }
    ],
    "request_body": None,
    "responses": [{"status_code": "200", "description": "Success"}],
}

FINDING = {
    "endpoint": "/accounts/{accountId}",
    "method": "GET",
    "rule": "Account ownership authorization is not described",
    "owasp_category": "API1:2023 Broken Object Level Authorization",
    "severity": "HIGH",
    "confidence": 0.72,
    "evidence": "A caller-controlled accountId selects account details.",
    "detected_by": "AI",
}


def response_json(status="SAFE", findings=None, endpoint=None, method="GET"):
    return json.dumps(
        {
            "endpoint": endpoint or CONTEXT["endpoint"]["path"],
            "method": method,
            "status": status,
            "findings": [] if findings is None else findings,
        }
    )


def test_prompt_includes_endpoint_path_method_and_context_data():
    prompt = build_security_analysis_prompt(CONTEXT)

    assert '"path": "/accounts/{accountId}"' in prompt
    assert '"method": "GET"' in prompt
    assert '"required_roles": [' in prompt
    assert '"account-reader"' in prompt


def test_prompt_requires_json_only_and_limits_runtime_claims():
    prompt = build_security_analysis_prompt(CONTEXT)

    assert "Return JSON only" in prompt
    assert "Do not claim that a vulnerability is runtime-exploitable" in prompt
    assert "Do not assume implementation details" in prompt


def test_prompt_omits_static_findings():
    context = {**CONTEXT, "static_findings": [{"secret": "STATIC_SENTINEL"}]}

    prompt = build_security_analysis_prompt(context)

    assert "STATIC_SENTINEL" not in prompt
    assert '"static_findings"' not in prompt


def test_mock_provider_returns_response_and_records_prompt():
    provider = MockLLMProvider(response="predefined")

    assert provider.generate("test prompt") == "predefined"
    assert provider.last_prompt == "test prompt"


def test_mock_provider_rejects_empty_prompt():
    provider = MockLLMProvider(response="predefined")

    with pytest.raises(ValueError):
        provider.generate("  ")


def test_response_parser_accepts_plain_json():
    result = parse_ai_response(response_json())

    assert isinstance(result, AIAnalysisResult)
    assert result.status == "SAFE"


@pytest.mark.parametrize(
    "opening_fence",
    ["```json", "```"],
)
def test_response_parser_accepts_fenced_json(opening_fence):
    raw_response = f"{opening_fence}\n{response_json()}\n```"

    assert parse_ai_response(raw_response).status == "SAFE"


def test_response_parser_rejects_malformed_json():
    with pytest.raises(json.JSONDecodeError):
        parse_ai_response('{"status": "SAFE"')


def test_response_parser_rejects_empty_response():
    with pytest.raises(ValueError):
        parse_ai_response("   ")


@pytest.mark.parametrize(
    ("field", "value"),
    [("severity", "URGENT"), ("confidence", 1.5)],
)
def test_response_parser_rejects_invalid_finding_values(field, value):
    finding = {**FINDING, field: value}

    with pytest.raises(ValidationError):
        parse_ai_response(response_json("POTENTIAL_VULNERABILITY", [finding]))


def test_response_parser_rejects_safe_result_with_findings():
    with pytest.raises(ValidationError):
        parse_ai_response(response_json("SAFE", [FINDING]))


def test_response_parser_rejects_vulnerability_result_without_findings():
    with pytest.raises(ValidationError):
        parse_ai_response(response_json("POTENTIAL_VULNERABILITY", []))


@pytest.mark.parametrize(
    "finding",
    [
        {**FINDING, "endpoint": "/other"},
        {**FINDING, "method": "POST"},
    ],
)
def test_response_parser_rejects_finding_conflicting_with_result(finding):
    with pytest.raises(ValidationError):
        parse_ai_response(response_json("POTENTIAL_VULNERABILITY", [finding]))


def test_analyzer_accepts_safe_mock_response_and_sends_prompt():
    provider = MockLLMProvider(response=response_json())

    result = analyze_endpoint(CONTEXT, provider)

    assert result.status == "SAFE"
    assert provider.last_prompt is not None
    assert '"path": "/accounts/{accountId}"' in provider.last_prompt


def test_analyzer_accepts_vulnerability_mock_response():
    provider = MockLLMProvider(
        response=response_json("POTENTIAL_VULNERABILITY", [FINDING])
    )

    result = analyze_endpoint(CONTEXT, provider)

    assert result.status == "POTENTIAL_VULNERABILITY"
    assert result.findings[0].confidence == 0.72


def test_analyzer_rejects_endpoint_mismatch():
    provider = MockLLMProvider(response=response_json(endpoint="/other"))

    with pytest.raises(ValueError, match="endpoint"):
        analyze_endpoint(CONTEXT, provider)


def test_analyzer_rejects_method_mismatch():
    provider = MockLLMProvider(response=response_json(method="POST"))

    with pytest.raises(ValueError, match="method"):
        analyze_endpoint(CONTEXT, provider)


def test_analyzer_does_not_mutate_context():
    context = deepcopy(CONTEXT)
    original = deepcopy(context)
    provider = MockLLMProvider(response=response_json())

    analyze_endpoint(context, provider)

    assert context == original


def test_parser_to_semantic_analyzer_integration():
    sample_path = Path(__file__).parents[1] / "sample_apis" / "sample_api.json"
    parsed = parse_openapi(str(sample_path))
    context = build_endpoint_context(
        parsed["endpoints"][0],
        parsed["api_info"],
        parsed["security_schemes"],
    )
    provider = MockLLMProvider(
        response=json.dumps(
            {
                "endpoint": context["endpoint"]["path"],
                "method": context["endpoint"]["method"],
                "status": "SAFE",
                "findings": [],
            }
        )
    )

    result = analyze_endpoint(context, provider)

    assert isinstance(result, AIAnalysisResult)
    assert result.endpoint == context["endpoint"]["path"]
    assert result.method == context["endpoint"]["method"]

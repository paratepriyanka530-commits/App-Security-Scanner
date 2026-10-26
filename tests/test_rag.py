import json
from copy import deepcopy

import pytest

from ai_analysis.knowledge.models import VulnerabilityPattern
from ai_analysis.knowledge.vulnerability_patterns import VULNERABILITY_PATTERNS
from ai_analysis.llm.mock_provider import MockLLMProvider
from ai_analysis.prompts import build_security_analysis_prompt
from ai_analysis.rag.query_builder import build_retrieval_query
from ai_analysis.rag.retriever import retrieve_relevant_knowledge
from ai_analysis.semantic_analyzer import analyze_endpoint


RAG_CONTEXT = {
    "api": {"title": "User API", "version": "1.0"},
    "endpoint": {
        "path": "/users/{userId}",
        "method": "PATCH",
        "summary": "Update a user profile",
        "description": "Updates the caller-selected user profile.",
    },
    "security": {
        "requirements": [{"oauth": ["profile:write"]}],
        "security_schemes": {
            "oauth": {"type": "oauth2", "scheme": "bearer"}
        },
        "required_roles": ["profile-editor"],
        "rate_limit": "20/minute",
        "required_security_headers": ["X-Request-ID"],
    },
    "parameters": [
        {
            "name": "userId",
            "location": "path",
            "required": True,
            "type": "string",
        },
        {
            "name": "callbackUrl",
            "location": "query",
            "required": False,
            "type": "string",
            "format": "uri",
        },
    ],
    "request_body": {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "displayName": {"type": "string"},
                        "role": {"type": "string"},
                    },
                }
            }
        }
    },
    "responses": [
        {
            "status_code": "200",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "password": {"type": "string"},
                        },
                    }
                }
            },
        }
    ],
}


def safe_response(context=RAG_CONTEXT):
    return json.dumps(
        {
            "endpoint": context["endpoint"]["path"],
            "method": context["endpoint"]["method"],
            "status": "SAFE",
            "findings": [],
        }
    )


def test_pattern_corpus_has_multiple_traceable_source_projects():
    sources = {pattern.source_project for pattern in VULNERABILITY_PATTERNS}

    assert len(VULNERABILITY_PATTERNS) == 20
    assert sources == {"OWASP crAPI", "VAmPI", "DVAPI"}
    assert all(pattern.source_reference.startswith("https://") for pattern in VULNERABILITY_PATTERNS)


def test_every_pattern_has_critical_content_indicators_and_limitations():
    for pattern in VULNERABILITY_PATTERNS:
        assert pattern.pattern_id
        assert pattern.title
        assert pattern.owasp_category.startswith("API")
        assert pattern.description
        assert pattern.vulnerability_pattern
        assert pattern.security_reasoning
        assert pattern.semantic_indicators
        assert pattern.limitations


def test_query_builder_includes_security_relevant_context_without_findings():
    query = build_retrieval_query(RAG_CONTEXT)

    assert "path: /users/{userId}" in query
    assert "method: PATCH" in query
    assert "userId path string" in query
    assert "callbackUrl query string uri" in query
    assert "request properties: displayName, role" in query
    assert "response properties: id, password" in query
    assert "profile:write" in query
    assert "profile-editor" in query
    assert "20/minute" in query
    assert "vulnerability" not in query.lower()
    assert "finding" not in query.lower()


@pytest.mark.parametrize(
    ("query", "expected_category_prefix"),
    [
        ("password field in response", "API3:2023"),
        ("caller controlled user id", "API1:2023"),
        ("admin state changing delete endpoint", "API5:2023"),
        ("callback URL webhook external server", "API7:2023"),
        ("coupon purchase signup flow abuse", "API6:2023"),
    ],
)
def test_retriever_ranks_semantically_related_category_first(
    query, expected_category_prefix
):
    results = retrieve_relevant_knowledge(query)

    assert results[0].owasp_category.startswith(expected_category_prefix)


def test_callback_query_retrieves_server_fetch_pattern():
    results = retrieve_relevant_knowledge(
        "callback URL webhook external server third party",
        top_k=3,
    )

    assert any(entry.owasp_category.startswith("API7:2023") for entry in results)


def test_retriever_honors_top_k_and_is_deterministic():
    query = "user id password response role"

    first = retrieve_relevant_knowledge(query, top_k=2)
    second = retrieve_relevant_knowledge(query, top_k=2)

    assert len(first) == 2
    assert first == second


def test_retriever_rejects_empty_query():
    with pytest.raises(ValueError, match="query"):
        retrieve_relevant_knowledge("  ")


def test_password_response_regression_ranks_api3_pattern_first():
    context = deepcopy(RAG_CONTEXT)
    context["endpoint"] = {
        "path": "/users",
        "method": "GET",
        "summary": "List users",
        "description": "Returns user records.",
    }
    context["parameters"] = []
    context["request_body"] = None

    results = retrieve_relevant_knowledge(build_retrieval_query(context), top_k=5)

    assert results[0].owasp_category.startswith("API3:")
    assert "password" in " ".join(results[0].api_shape.response_field_patterns)


def test_user_id_resource_regression_ranks_bola_pattern_first():
    context = deepcopy(RAG_CONTEXT)
    context["endpoint"] = {
        "path": "/users/{id}",
        "method": "GET",
        "summary": "Retrieve user",
        "description": "Returns the caller-selected user resource.",
    }
    context["parameters"] = [
        {"name": "id", "location": "path", "required": True, "type": "string"}
    ]
    context["request_body"] = None
    context["responses"] = []

    results = retrieve_relevant_knowledge(build_retrieval_query(context), top_k=5)

    assert results[0].owasp_category.startswith("API1:")


def test_prompt_contains_grounding_indicators_limitations_and_caution():
    pattern = next(
        item
        for item in VULNERABILITY_PATTERNS
        if item.owasp_category.startswith("API3:")
    )

    prompt = build_security_analysis_prompt(RAG_CONTEXT, [pattern])

    assert "Retrieved similar vulnerable API patterns" in prompt
    assert pattern.source_project in prompt
    assert pattern.owasp_category in prompt
    assert pattern.vulnerability_pattern in prompt
    assert pattern.security_reasoning in prompt
    assert pattern.limitations[0] in prompt
    assert "examples, not proof" in prompt
    assert "important differences" in prompt


def test_rag_prompt_does_not_include_static_findings():
    context = {**RAG_CONTEXT, "static_findings": [{"secret": "STATIC_SENTINEL"}]}
    pattern = VULNERABILITY_PATTERNS[0]

    prompt = build_security_analysis_prompt(context, [pattern])

    assert "STATIC_SENTINEL" not in prompt
    assert '"static_findings"' not in prompt


def test_analyzer_non_rag_behavior_remains_available():
    provider = MockLLMProvider(safe_response())

    result = analyze_endpoint(RAG_CONTEXT, provider)

    assert result.status == "SAFE"
    assert "Retrieved similar vulnerable API patterns" not in provider.last_prompt


def test_rag_analyzer_invokes_retriever_and_grounding_reaches_provider():
    captured_queries = []
    api3_pattern = next(
        pattern
        for pattern in VULNERABILITY_PATTERNS
        if pattern.owasp_category.startswith("API3:")
    )

    def recording_retriever(query: str) -> list[VulnerabilityPattern]:
        captured_queries.append(query)
        return [api3_pattern]

    provider = MockLLMProvider(safe_response())
    result = analyze_endpoint(RAG_CONTEXT, provider, retriever=recording_retriever)

    assert result.status == "SAFE"
    assert captured_queries
    assert "password" in captured_queries[0]
    assert "Retrieved similar vulnerable API patterns" in provider.last_prompt
    assert api3_pattern.pattern_id not in provider.last_prompt
    assert api3_pattern.owasp_category in provider.last_prompt


def test_rag_analyzer_invalid_model_output_still_fails():
    provider = MockLLMProvider("not valid JSON")

    with pytest.raises(json.JSONDecodeError):
        analyze_endpoint(
            RAG_CONTEXT,
            provider,
            retriever=retrieve_relevant_knowledge,
        )


def test_rag_analyzer_does_not_mutate_context():
    context = deepcopy(RAG_CONTEXT)
    original = deepcopy(context)
    provider = MockLLMProvider(safe_response(context))

    analyze_endpoint(context, provider, retriever=retrieve_relevant_knowledge)

    assert context == original

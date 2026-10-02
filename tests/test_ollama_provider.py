import json
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from ai_analysis.context_builder import build_endpoint_context
from ai_analysis.llm.ollama_provider import (
    OllamaConnectionError,
    OllamaProvider,
    OllamaResponseError,
)
from ai_analysis.schemas import AIAnalysisResult
from ai_analysis.semantic_analyzer import analyze_endpoint
from parser.openapi_parser import parse_openapi


def mocked_http_response(body, status=200):
    response = MagicMock()
    response.getcode.return_value = status
    response.read.return_value = body
    response.__enter__.return_value = response
    return response


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_valid_prompt_sends_configured_non_streaming_request(mock_urlopen):
    mock_urlopen.return_value = mocked_http_response(
        json.dumps({"response": "generated text"}).encode()
    )
    provider = OllamaProvider(
        model="example-model:latest",
        base_url="http://localhost:11434/",
        timeout=45,
    )

    result = provider.generate("Analyze this endpoint")

    assert result == "generated text"
    request = mock_urlopen.call_args.args[0]
    request_payload = json.loads(request.data.decode())
    assert request.full_url == "http://localhost:11434/api/generate"
    assert request.get_method() == "POST"
    assert request_payload == {
        "model": "example-model:latest",
        "prompt": "Analyze this endpoint",
        "stream": False,
        "format": "json",
    }
    assert mock_urlopen.call_args.kwargs["timeout"] == 45.0


def test_empty_prompt_is_rejected_without_network_access():
    provider = OllamaProvider(model="example-model")

    with pytest.raises(ValueError, match="prompt"):
        provider.generate("  ")


def test_empty_model_is_rejected():
    with pytest.raises(ValueError, match="model"):
        OllamaProvider(model="  ")


@pytest.mark.parametrize("base_url", ["localhost:11434", "ftp://localhost"])
def test_invalid_base_url_is_rejected(base_url):
    with pytest.raises(ValueError, match="base_url"):
        OllamaProvider(model="example-model", base_url=base_url)


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_connection_failure_raises_provider_error(mock_urlopen):
    mock_urlopen.side_effect = URLError(ConnectionRefusedError())

    with pytest.raises(OllamaConnectionError, match="connect"):
        OllamaProvider(model="example-model").generate("prompt")


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_timeout_raises_provider_error(mock_urlopen):
    mock_urlopen.side_effect = socket.timeout()

    with pytest.raises(OllamaConnectionError, match="timed out"):
        OllamaProvider(model="example-model").generate("prompt")


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_http_error_raises_provider_error(mock_urlopen):
    mock_urlopen.side_effect = HTTPError(
        "http://localhost:11434/api/generate", 500, "error", {}, None
    )

    with pytest.raises(OllamaResponseError, match="500"):
        OllamaProvider(model="example-model").generate("prompt")


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_malformed_ollama_json_raises_provider_error(mock_urlopen):
    mock_urlopen.return_value = mocked_http_response(b"not-json")

    with pytest.raises(OllamaResponseError, match="invalid JSON"):
        OllamaProvider(model="example-model").generate("prompt")


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"response": None},
        {"response": "  "},
    ],
)
@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_missing_response_text_raises_provider_error(mock_urlopen, body):
    mock_urlopen.return_value = mocked_http_response(json.dumps(body).encode())

    with pytest.raises(OllamaResponseError, match="generated text"):
        OllamaProvider(model="example-model").generate("prompt")


def run_mocked_ollama_analysis(mock_urlopen, status, findings):
    sample_path = Path(__file__).parents[1] / "sample_apis" / "sample_api.json"
    parsed = parse_openapi(str(sample_path))
    context = build_endpoint_context(
        parsed["endpoints"][0],
        parsed["api_info"],
        parsed["security_schemes"],
    )
    ai_result = {
        "endpoint": context["endpoint"]["path"],
        "method": context["endpoint"]["method"],
        "status": status,
        "findings": findings,
    }
    mock_urlopen.return_value = mocked_http_response(
        json.dumps({"response": json.dumps(ai_result)}).encode()
    )

    result = analyze_endpoint(
        context,
        OllamaProvider(model="example-integration-model"),
    )
    return context, result


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_parser_to_ollama_analyzer_safe_integration(mock_urlopen):
    context, result = run_mocked_ollama_analysis(mock_urlopen, "SAFE", [])

    assert isinstance(result, AIAnalysisResult)
    assert result.status == "SAFE"
    assert result.endpoint == context["endpoint"]["path"]


@patch("ai_analysis.llm.ollama_provider.urlopen")
def test_parser_to_ollama_analyzer_vulnerability_integration(mock_urlopen):
    finding = {
        "endpoint": "/users",
        "method": "GET",
        "rule": "Collection authorization semantics require review",
        "owasp_category": "API5:2023 Broken Function Level Authorization",
        "severity": "MEDIUM",
        "confidence": 0.64,
        "evidence": "The operation returns a user collection.",
        "detected_by": "AI",
    }
    _, result = run_mocked_ollama_analysis(
        mock_urlopen,
        "POTENTIAL_VULNERABILITY",
        [finding],
    )

    assert isinstance(result, AIAnalysisResult)
    assert result.status == "POTENTIAL_VULNERABILITY"
    assert len(result.findings) == 1
    assert result.findings[0].owasp_category.startswith("API5:2023")

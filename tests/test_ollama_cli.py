import argparse
import sys
from unittest.mock import MagicMock, patch

from scripts import test_ollama_ai


PARSED_API = {
    "api_info": {"title": "Test API"},
    "security_schemes": {},
    "endpoints": [{"path": "/users", "method": "GET"}],
}
CONTEXT = {"endpoint": {"path": "/users", "method": "GET"}}


def cli_arguments(rag=False):
    return argparse.Namespace(
        openapi_file="api.yaml",
        model="example-model",
        base_url="http://ollama.test:11434",
        timeout=45.0,
        endpoint_index=0,
        rag=rag,
    )


def mocked_result():
    result = MagicMock()
    result.model_dump_json.return_value = '{"status":"SAFE"}'
    return result


@patch("scripts.test_ollama_ai.analyze_endpoint")
@patch("scripts.test_ollama_ai.OllamaProvider")
@patch("scripts.test_ollama_ai.build_endpoint_context", return_value=CONTEXT)
@patch("scripts.test_ollama_ai.parse_openapi", return_value=PARSED_API)
@patch("scripts.test_ollama_ai.parse_arguments", return_value=cli_arguments())
def test_default_mode_uses_no_retriever_and_preserves_options(
    mock_arguments,
    mock_parse,
    mock_context_builder,
    mock_provider_class,
    mock_analyze,
    capsys,
):
    result = mocked_result()
    provider = mock_provider_class.return_value
    mock_analyze.return_value = result

    test_ollama_ai.main()

    mock_parse.assert_called_once_with("api.yaml")
    mock_context_builder.assert_called_once_with(
        PARSED_API["endpoints"][0],
        PARSED_API["api_info"],
        PARSED_API["security_schemes"],
    )
    mock_provider_class.assert_called_once_with(
        model="example-model",
        base_url="http://ollama.test:11434",
        timeout=45.0,
    )
    mock_analyze.assert_called_once_with(CONTEXT, provider)
    assert capsys.readouterr().out.strip() == '{"status":"SAFE"}'


@patch("scripts.test_ollama_ai.analyze_endpoint")
@patch("scripts.test_ollama_ai.OllamaProvider")
@patch("scripts.test_ollama_ai.build_endpoint_context", return_value=CONTEXT)
@patch("scripts.test_ollama_ai.parse_openapi", return_value=PARSED_API)
@patch("scripts.test_ollama_ai.parse_arguments", return_value=cli_arguments(rag=True))
def test_rag_mode_supplies_curated_knowledge_retriever(
    mock_arguments,
    mock_parse,
    mock_context_builder,
    mock_provider_class,
    mock_analyze,
    capsys,
):
    result = mocked_result()
    provider = mock_provider_class.return_value
    mock_analyze.return_value = result

    test_ollama_ai.main()

    mock_analyze.assert_called_once_with(
        CONTEXT,
        provider,
        retriever=test_ollama_ai.retrieve_relevant_knowledge,
    )
    assert capsys.readouterr().out.strip() == '{"status":"SAFE"}'


def test_cli_parses_existing_options_and_rag_flag(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_ollama_ai.py",
            "custom.yaml",
            "--model",
            "custom-model",
            "--base-url",
            "http://localhost:22000",
            "--timeout",
            "30",
            "--endpoint-index",
            "2",
            "--rag",
        ],
    )

    arguments = test_ollama_ai.parse_arguments()

    assert arguments.openapi_file == "custom.yaml"
    assert arguments.model == "custom-model"
    assert arguments.base_url == "http://localhost:22000"
    assert arguments.timeout == 30.0
    assert arguments.endpoint_index == 2
    assert arguments.rag is True

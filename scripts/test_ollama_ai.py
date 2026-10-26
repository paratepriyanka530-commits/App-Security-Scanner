"""Manually run semantic analysis for one endpoint through local Ollama."""

import argparse
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_analysis.context_builder import build_endpoint_context
from ai_analysis.llm.ollama_provider import OllamaProvider
from ai_analysis.rag.retriever import retrieve_relevant_knowledge
from ai_analysis.semantic_analyzer import analyze_endpoint
from parser.openapi_parser import parse_openapi


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run AI semantic analysis for one parsed OpenAPI endpoint."
    )
    parser.add_argument("openapi_file", help="Path to an OpenAPI JSON/YAML file")
    parser.add_argument(
        "--model",
        default=os.environ.get("OLLAMA_MODEL"),
        help="Ollama model name (or set OLLAMA_MODEL)",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
        help="Ollama base URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Request timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--endpoint-index",
        type=int,
        default=0,
        help="Zero-based parsed endpoint index (default: 0)",
    )
    parser.add_argument(
        "--rag",
        action="store_true",
        help="Ground semantic analysis with curated OWASP knowledge",
    )
    arguments = parser.parse_args()
    if not arguments.model or not arguments.model.strip():
        parser.error("provide --model or set OLLAMA_MODEL")
    return arguments


def main() -> None:
    arguments = parse_arguments()
    parsed = parse_openapi(arguments.openapi_file)

    try:
        endpoint = parsed["endpoints"][arguments.endpoint_index]
    except IndexError as error:
        raise SystemExit(
            f"Endpoint index {arguments.endpoint_index} is out of range "
            f"for {len(parsed['endpoints'])} parsed endpoints."
        ) from error

    context = build_endpoint_context(
        endpoint,
        parsed["api_info"],
        parsed["security_schemes"],
    )
    provider = OllamaProvider(
        model=arguments.model,
        base_url=arguments.base_url,
        timeout=arguments.timeout,
    )
    if arguments.rag:
        result = analyze_endpoint(
            context,
            provider,
            retriever=retrieve_relevant_knowledge,
        )
    else:
        result = analyze_endpoint(context, provider)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()

"""Orchestration for model-agnostic endpoint semantic analysis."""

from collections.abc import Callable

from ai_analysis.knowledge.models import VulnerabilityPattern
from ai_analysis.llm.base import LLMProvider
from ai_analysis.prompts import build_security_analysis_prompt
from ai_analysis.rag.query_builder import build_retrieval_query
from ai_analysis.response_parser import parse_ai_response
from ai_analysis.schemas import AIAnalysisResult


def analyze_endpoint(
    context: dict,
    provider: LLMProvider,
    retriever: Callable[[str], list[VulnerabilityPattern]] | None = None,
) -> AIAnalysisResult:
    """Analyze one prepared endpoint context using the supplied provider."""
    if not isinstance(context, dict):
        raise TypeError("context must be a dictionary")
    if not isinstance(provider, LLMProvider):
        raise TypeError("provider must implement LLMProvider")
    if retriever is not None and not callable(retriever):
        raise TypeError("retriever must be callable")

    endpoint = context.get("endpoint")
    if not isinstance(endpoint, dict):
        raise ValueError("context must contain an endpoint dictionary")

    path = endpoint.get("path")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("context endpoint must contain a non-empty path")

    method = endpoint.get("method")
    if not isinstance(method, str) or not method.strip():
        raise ValueError("context endpoint must contain a non-empty method")

    retrieved_knowledge = None
    if retriever is not None:
        query = build_retrieval_query(context)
        retrieved_knowledge = retriever(query)

    prompt = build_security_analysis_prompt(context, retrieved_knowledge)
    raw_response = provider.generate(prompt)
    result = parse_ai_response(raw_response)

    if result.endpoint != path:
        raise ValueError("AI response endpoint does not match the supplied context")
    if result.method != method.upper():
        raise ValueError("AI response method does not match the supplied context")

    return result

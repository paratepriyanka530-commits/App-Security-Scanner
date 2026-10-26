"""Lightweight deterministic retrieval over vulnerable API patterns."""

import re

from ai_analysis.knowledge.models import VulnerabilityPattern
from ai_analysis.knowledge.vulnerability_patterns import VULNERABILITY_PATTERNS


_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a", "an", "and", "api", "as", "at", "be", "by", "for", "from",
    "in", "is", "of", "on", "or", "the", "to", "with",
    "description", "header", "headers", "method", "parameter", "parameters",
    "path", "properties", "property", "request", "required", "requirements",
    "response", "scheme", "schemes", "security", "summary", "type",
}


def _tokens(text: str) -> set[str]:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    tokens = {
        token
        for token in _TOKEN_PATTERN.findall(camel_split.lower())
        if token not in _STOP_WORDS and len(token) > 1
    }
    tokens.update(
        token[:-1]
        for token in tuple(tokens)
        if token.endswith("s") and len(token) > 3
    )
    return tokens


def _entry_score(query_tokens: set[str], pattern: VulnerabilityPattern) -> int:
    shape = pattern.api_shape
    weighted_fields = (
        (pattern.owasp_category, 1),
        (pattern.title, 5),
        (pattern.description, 2),
        (" ".join(shape.methods), 2),
        (" ".join(shape.path_patterns), 8),
        (" ".join(shape.parameter_patterns), 7),
        (" ".join(shape.request_field_patterns), 9),
        (" ".join(shape.response_field_patterns), 10),
        (" ".join(pattern.semantic_context), 5),
        (pattern.vulnerability_pattern, 7),
        (pattern.security_reasoning, 3),
        (" ".join(pattern.semantic_indicators), 9),
        (" ".join(pattern.evidence_to_compare), 4),
    )
    return sum(
        weight * len(query_tokens & _tokens(text))
        for text, weight in weighted_fields
    )


def retrieve_relevant_knowledge(
    query: str,
    top_k: int = 3,
) -> list[VulnerabilityPattern]:
    """Return similar public patterns; internal scores are not AI confidence."""
    if not isinstance(query, str):
        raise TypeError("query must be a string")
    if not query.strip():
        raise ValueError("query must not be empty")
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise TypeError("top_k must be an integer")
    if top_k <= 0:
        raise ValueError("top_k must be greater than zero")

    query_tokens = _tokens(query)
    ranked = [
        (_entry_score(query_tokens, pattern), index, pattern)
        for index, pattern in enumerate(VULNERABILITY_PATTERNS)
    ]
    ranked.sort(key=lambda item: (-item[0], item[1]))

    return [
        pattern
        for score, _, pattern in ranked[:top_k]
        if score > 0
    ]


retrieve_relevant_patterns = retrieve_relevant_knowledge

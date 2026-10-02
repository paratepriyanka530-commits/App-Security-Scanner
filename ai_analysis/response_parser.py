"""Strict parsing and validation for semantic-analysis responses."""

import json
import re

from ai_analysis.schemas import AIAnalysisResult


_CODE_FENCE = re.compile(
    r"\A```(?:json)?[ \t]*\r?\n(?P<body>.*?)\r?\n```[ \t]*\Z",
    flags=re.DOTALL | re.IGNORECASE,
)


def parse_ai_response(raw_response: str) -> AIAnalysisResult:
    """Parse plain or singly fenced JSON into a validated analysis result."""
    if not isinstance(raw_response, str):
        raise TypeError("raw_response must be a string")

    response = raw_response.strip()
    if not response:
        raise ValueError("raw_response must not be empty")

    fence_match = _CODE_FENCE.fullmatch(response)
    if fence_match:
        response = fence_match.group("body").strip()

    parsed = json.loads(response)
    return AIAnalysisResult.model_validate(parsed)

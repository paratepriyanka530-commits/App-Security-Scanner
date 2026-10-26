"""Deterministic identity matching for static and AI findings."""

import re
from collections.abc import Mapping
from typing import Any


_OWASP_CATEGORY = re.compile(
    r"^\s*API\s*(10|[1-9])(?:\s*:\s*(\d{4}))?(?:\b|\s|-|$)",
    flags=re.IGNORECASE,
)


def normalize_owasp_category(category: str) -> str:
    """Normalize equivalent 2023 full and short labels to their API number."""
    if not isinstance(category, str):
        raise TypeError("OWASP category must be a string")
    if not category.strip():
        raise ValueError("OWASP category must not be empty")

    match = _OWASP_CATEGORY.match(category)
    if match:
        api_number, year = match.groups()
        if year and year != "2023":
            return f"API{api_number}:{year}"
        return f"API{api_number}"

    return " ".join(category.casefold().split())


def _value(finding: Any, field: str) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(field)
    return getattr(finding, field, None)


def findings_match(static_finding: Any, ai_finding: Any) -> bool:
    """Return whether two findings identify the same endpoint issue category."""
    static_endpoint = _value(static_finding, "endpoint")
    ai_endpoint = _value(ai_finding, "endpoint")
    static_method = _value(static_finding, "method")
    ai_method = _value(ai_finding, "method")
    static_category = _value(static_finding, "owasp_category")
    ai_category = _value(ai_finding, "owasp_category")

    if not all(
        isinstance(value, str) and value.strip()
        for value in (
            static_endpoint,
            ai_endpoint,
            static_method,
            ai_method,
            static_category,
            ai_category,
        )
    ):
        return False

    return (
        static_endpoint == ai_endpoint
        and static_method.upper() == ai_method.upper()
        and normalize_owasp_category(static_category)
        == normalize_owasp_category(ai_category)
    )

"""Normalized identity matching for evaluation labels and predictions."""

from ai_analysis.validation.matcher import normalize_owasp_category


EvaluationKey = tuple[str, str, str]
EndpointKey = tuple[str, str]


def endpoint_key(endpoint: str, method: str) -> EndpointKey:
    """Build a normalized endpoint/method identity."""
    return endpoint, method.upper()


def evaluation_key(
    endpoint: str,
    method: str,
    owasp_category: str,
) -> EvaluationKey:
    """Build the endpoint/method/normalized-category evaluation unit."""
    return endpoint, method.upper(), normalize_owasp_category(owasp_category)


def prediction_matches_label(
    prediction_endpoint: str,
    prediction_method: str,
    prediction_category: str,
    label_endpoint: str,
    label_method: str,
    label_category: str,
) -> bool:
    """Match only when the complete evaluation unit is equal."""
    return evaluation_key(
        prediction_endpoint,
        prediction_method,
        prediction_category,
    ) == evaluation_key(label_endpoint, label_method, label_category)

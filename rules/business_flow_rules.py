"""Static indicators for sensitive business flows."""


SENSITIVE_BUSINESS_FLOW_KEYWORDS = {
    "payment",
    "payments",
    "checkout",
    "transfer",
    "withdraw",
    "withdrawal",
    "refund",
    "purchase",
}


def check_sensitive_business_flow(endpoint):
    """
    Identify potentially sensitive business flows.

    This rule is intentionally conservative. It reports only
    business-flow indicators and does not claim exploitation.
    """
    path = endpoint.get(
        "path",
        "",
    ).lower()

    if not any(
        keyword in path
        for keyword in SENSITIVE_BUSINESS_FLOW_KEYWORDS
    ):
        return []

    if endpoint.get("rate_limit"):
        return []

    return [
        {
            "rule": "Potential Sensitive Business Flow Abuse",
            "severity": "MEDIUM",
            "message": (
                f"{endpoint.get('method')} "
                f"{endpoint.get('path')} appears to expose a "
                "sensitive business flow without documented "
                "rate limiting."
            ),
        }
    ]
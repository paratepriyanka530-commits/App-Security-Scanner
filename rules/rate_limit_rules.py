"""Rate-limit rules using the documented ``x-rate-limit`` extension."""

RATE_LIMIT_KEYWORDS = {"login", "signin", "signup", "register", "otp", "password", "reset", "verify"}


def check_rate_limiting(endpoint):
    path = endpoint.get("path", "").lower()
    if any(keyword in path for keyword in RATE_LIMIT_KEYWORDS) and not endpoint.get("rate_limit"):
        return [{"rule": "Missing Rate Limiting", "severity": "MEDIUM", "message": f"Sensitive endpoint {endpoint.get('path')} has no documented x-rate-limit."}]
    return []

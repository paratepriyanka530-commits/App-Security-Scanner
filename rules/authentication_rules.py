"""Authentication and sensitive-data rules for normalized endpoints."""

SENSITIVE_FIELDS = {"password", "secret", "token", "access_token", "refresh_token", "api_key", "apikey", "credit_card", "card_number", "cvv", "ssn"}
AUTH_SENSITIVE_KEYWORDS = {"user", "users", "account", "accounts", "admin", "profile", "payment", "payments", "order", "orders"}
DANGEROUS_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _finding(rule, severity, message):
    return {"rule": rule, "severity": severity, "message": message}


def check_missing_authentication(endpoint):
    path = endpoint.get("path", "").lower()
    if endpoint.get("security"):
        return []
    if any(keyword in path for keyword in AUTH_SENSITIVE_KEYWORDS):
        return [_finding("Missing Authentication", "HIGH", f"Sensitive endpoint {endpoint.get('method')} {endpoint.get('path')} has no authentication requirement.")]
    return []


def _find_sensitive_keys(data, found):
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in SENSITIVE_FIELDS:
                found.add(str(key))
            _find_sensitive_keys(value, found)
    elif isinstance(data, list):
        for item in data:
            _find_sensitive_keys(item, found)


def check_sensitive_data_exposure(endpoint):
    found = set()
    for response in endpoint.get("responses", []):
        _find_sensitive_keys(response.get("content", {}), found)
    return [_finding("Sensitive Data Exposure", "HIGH", f"Sensitive field '{field}' may be exposed in an API response.") for field in sorted(found)]


def check_dangerous_method_security(endpoint):
    method = endpoint.get("method", "").upper()
    if method in DANGEROUS_METHODS and not endpoint.get("security"):
        return [_finding("Dangerous Operation Without Security", "HIGH", f"{method} operation {endpoint.get('path')} does not define security requirements.")]
    return []

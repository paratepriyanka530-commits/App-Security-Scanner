"""
Person 2 - Security Rules Module
Designed to work with the normalized endpoint format produced by parser/openapi_parser.py
"""

SENSITIVE_FIELDS = {
    "password", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "credit_card", "card_number", "cvv", "ssn"
}

AUTH_SENSITIVE_KEYWORDS = {
    "user", "users", "account", "accounts", "admin", "profile",
    "payment", "payments", "order", "orders"
}

RATE_LIMIT_KEYWORDS = {
    "login", "signin", "signup", "register", "otp",
    "password", "reset", "verify"
}

DANGEROUS_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _finding(rule, severity, message):
    return {
        "rule": rule,
        "severity": severity,
        "message": message
    }


# RULE 1: Missing authentication on sensitive endpoints
def check_missing_authentication(endpoint):
    path = endpoint.get("path", "").lower()
    security = endpoint.get("security", [])

    if security:
        return []

    if any(keyword in path for keyword in AUTH_SENSITIVE_KEYWORDS):
        return [_finding(
            "Missing Authentication",
            "HIGH",
            f"Sensitive endpoint {endpoint.get('method')} {endpoint.get('path')} has no authentication requirement."
        )]

    return []


# RULE 2: Sensitive data exposed in API responses
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

    return [
        _finding(
            "Sensitive Data Exposure",
            "HIGH",
            f"Sensitive field '{field}' may be exposed in an API response."
        )
        for field in sorted(found)
    ]


# RULE 3: Missing input validation
# Uses validation fields when available in normalized parameters.
def check_input_validation(endpoint):
    findings = []

    for parameter in endpoint.get("parameters", []):
        name = parameter.get("name", "unknown")
        schema_type = parameter.get("type")

        if schema_type == "string":
            has_validation = any(
                parameter.get(key) is not None
                for key in ("minLength", "maxLength", "pattern", "enum")
            )

            if not has_validation:
                findings.append(_finding(
                    "Missing Input Validation",
                    "MEDIUM",
                    f"String parameter '{name}' has no length, pattern, or enum validation."
                ))

        elif schema_type in ("integer", "number"):
            has_validation = any(
                parameter.get(key) is not None
                for key in ("minimum", "maximum", "enum")
            )

            if not has_validation:
                findings.append(_finding(
                    "Missing Input Validation",
                    "MEDIUM",
                    f"Numeric parameter '{name}' has no range or enum validation."
                ))

    return findings


# RULE 4: Missing rate limiting on authentication-sensitive endpoints
def check_rate_limiting(endpoint):
    path = endpoint.get("path", "").lower()
    rate_limit = endpoint.get("rate_limit")

    if any(keyword in path for keyword in RATE_LIMIT_KEYWORDS) and not rate_limit:
        return [_finding(
            "Missing Rate Limiting",
            "MEDIUM",
            f"Sensitive endpoint {endpoint.get('path')} has no documented rate limit."
        )]

    return []


# RULE 5: Dangerous HTTP operation without security
def check_dangerous_method_security(endpoint):
    method = endpoint.get("method", "").upper()
    security = endpoint.get("security", [])

    if method in DANGEROUS_METHODS and not security:
        return [_finding(
            "Dangerous Operation Without Security",
            "HIGH",
            f"{method} operation {endpoint.get('path')} does not define security requirements."
        )]

    return []


def run_all_rules(endpoint):
    findings = []

    findings.extend(check_missing_authentication(endpoint))
    findings.extend(check_sensitive_data_exposure(endpoint))
    findings.extend(check_input_validation(endpoint))
    findings.extend(check_rate_limiting(endpoint))
    findings.extend(check_dangerous_method_security(endpoint))

    return findings

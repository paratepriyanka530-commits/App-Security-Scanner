"""Validate response headers required by ``x-required-security-headers``."""


def check_security_headers(endpoint):
    required = endpoint.get("required_security_headers", [])
    if not required:
        return []
    declared = set()
    for response in endpoint.get("responses", []):
        declared.update(name.lower() for name in response.get("headers", {}))
    return [{"rule": "Missing Security Header", "severity": "MEDIUM", "message": f"{endpoint.get('method')} {endpoint.get('path')} does not document required header '{name}'."} for name in required if name.lower() not in declared]

"""Build LLM-ready context from the existing parser's normalized output."""

from copy import deepcopy


def build_endpoint_context(
    endpoint: dict,
    api_info: dict | None = None,
    security_schemes: dict | None = None,
) -> dict:
    """Create an independent context copy for one normalized endpoint."""
    if not isinstance(endpoint, dict):
        raise TypeError("endpoint must be a dictionary")

    path = endpoint.get("path")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("endpoint must contain a non-empty path")

    method = endpoint.get("method")
    if not isinstance(method, str) or not method.strip():
        raise ValueError("endpoint must contain a non-empty method")

    return {
        "api": deepcopy(api_info) if api_info is not None else {},
        "endpoint": {
            "path": deepcopy(path),
            "method": method.upper(),
            "summary": deepcopy(endpoint.get("summary")),
            "description": deepcopy(endpoint.get("description")),
        },
        "security": {
            "requirements": deepcopy(endpoint.get("security")),
            "security_schemes": (
                deepcopy(security_schemes)
                if security_schemes is not None
                else {}
            ),
            "required_roles": deepcopy(endpoint.get("required_roles")),
            "rate_limit": deepcopy(endpoint.get("rate_limit")),
            "required_security_headers": deepcopy(
                endpoint.get("required_security_headers")
            ),
        },
        "parameters": deepcopy(endpoint.get("parameters", [])),
        "request_body": deepcopy(endpoint.get("request_body")),
        "responses": deepcopy(endpoint.get("responses", [])),
    }

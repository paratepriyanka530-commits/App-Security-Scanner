"""Build neutral retrieval queries from normalized endpoint context."""

import json


def _property_names(value: object) -> list[str]:
    names: list[str] = []

    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            names.extend(str(name) for name in properties)
        for nested_value in value.values():
            names.extend(_property_names(nested_value))
    elif isinstance(value, list):
        for item in value:
            names.extend(_property_names(item))

    return list(dict.fromkeys(names))


def _compact_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def build_retrieval_query(context: dict) -> str:
    """Represent security-relevant endpoint metadata without making findings."""
    if not isinstance(context, dict):
        raise TypeError("context must be a dictionary")
    if not context:
        raise ValueError("context must not be empty")

    endpoint = context.get("endpoint")
    if not isinstance(endpoint, dict):
        raise ValueError("context must contain an endpoint dictionary")

    parts = [
        f"path: {endpoint.get('path', '')}",
        f"method: {endpoint.get('method', '')}",
        f"summary: {endpoint.get('summary') or ''}",
        f"description: {endpoint.get('description') or ''}",
    ]

    parameter_descriptions = []
    for parameter in context.get("parameters") or []:
        if isinstance(parameter, dict):
            details = [
                str(parameter.get("name") or ""),
                str(parameter.get("location") or ""),
                str(parameter.get("type") or ""),
                str(parameter.get("format") or ""),
            ]
            parameter_descriptions.append(" ".join(item for item in details if item))
    parts.append(f"parameters: {'; '.join(parameter_descriptions)}")

    request_properties = _property_names(context.get("request_body"))
    response_properties = _property_names(context.get("responses"))
    parts.append(f"request properties: {', '.join(request_properties)}")
    parts.append(f"response properties: {', '.join(response_properties)}")

    security = context.get("security")
    if isinstance(security, dict):
        parts.append(
            f"security requirements: {_compact_json(security.get('requirements'))}"
        )
        parts.append(
            f"security schemes: {_compact_json(security.get('security_schemes'))}"
        )
        parts.append(f"required roles: {_compact_json(security.get('required_roles'))}")
        parts.append(f"rate limit: {_compact_json(security.get('rate_limit'))}")
        parts.append(
            "required security headers: "
            f"{_compact_json(security.get('required_security_headers'))}"
        )

    return "\n".join(parts)

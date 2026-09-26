"""Static checks for potentially unsafe consumption of external APIs."""


def _finding(rule, severity, message):
    return {
        "rule": rule,
        "severity": severity,
        "message": message,
    }


def check_api_consumption(parsed_api):
    """
    Detect external API/server references that lack documented controls.

    This is a static contract-level indicator. It does not prove that
    an external service is unsafe or compromised.
    """
    findings = []

    if not isinstance(parsed_api, dict):
        return findings

    endpoints = parsed_api.get("endpoints", [])

    for endpoint in endpoints:
        request_body = endpoint.get("request_body") or {}
        content = request_body.get("content", {})

        if not isinstance(content, dict):
            continue

        for media_type, media_data in content.items():
            if not isinstance(media_data, dict):
                continue

            schema = media_data.get("schema", {})

            if not isinstance(schema, dict):
                continue

            properties = schema.get("properties", {})

            if not isinstance(properties, dict):
                continue

            for name, property_schema in properties.items():
                if not isinstance(property_schema, dict):
                    continue

                if property_schema.get("format") in {"uri", "url"}:
                    findings.append(
                        _finding(
                            "Potential Unsafe API Consumption",
                            "MEDIUM",
                            (
                                f"{endpoint.get('method')} "
                                f"{endpoint.get('path')} accepts "
                                f"URL-like external input '{name}' "
                                "without documented validation or "
                                "allowlist controls."
                            ),
                        )
                    )

    return findings
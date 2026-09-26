"""Static API inventory checks for an OpenAPI specification."""


def _finding(rule, severity, message):
    return {
        "rule": rule,
        "severity": severity,
        "message": message,
    }


def check_api_inventory(parsed_api):
    """
    Check whether the OpenAPI contract contains basic inventory metadata.

    This is a static documentation indicator. It does not prove that
    undocumented API versions or endpoints exist in production.
    """
    findings = []

    if not isinstance(parsed_api, dict):
        return findings

    api_info = parsed_api.get("api_info", {})
    endpoints = parsed_api.get("endpoints", [])

    if not api_info.get("title"):
        findings.append(
            _finding(
                "Incomplete API Inventory",
                "LOW",
                "The OpenAPI document does not define an API title.",
            )
        )

    if not api_info.get("version"):
        findings.append(
            _finding(
                "Incomplete API Inventory",
                "LOW",
                "The OpenAPI document does not define an API version.",
            )
        )

    if not api_info.get("openapi_version"):
        findings.append(
            _finding(
                "Incomplete API Inventory",
                "LOW",
                "The OpenAPI document does not define an OpenAPI version.",
            )
        )

    if not endpoints:
        findings.append(
            _finding(
                "Empty API Inventory",
                "MEDIUM",
                "The OpenAPI document does not contain any documented API endpoints.",
            )
        )

    return findings
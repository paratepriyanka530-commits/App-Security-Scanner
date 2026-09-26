"""Static resource-consumption checks for normalized OpenAPI endpoints."""


PAGINATION_NAMES = {
    "limit",
    "page_size",
    "pagesize",
    "page_limit",
    "count",
    "offset",
}


def _finding(rule, severity, message):
    return {
        "rule": rule,
        "severity": severity,
        "message": message,
    }


def check_resource_consumption(endpoint):
    """
    Detect potentially unbounded resource-consuming inputs.

    This is a static contract-level indicator. It does not prove
    that the deployed API is vulnerable.
    """
    findings = []

    for parameter in endpoint.get("parameters", []):
        name = str(parameter.get("name", "")).lower()
        parameter_type = parameter.get("type")

        if name in PAGINATION_NAMES:
            if (
                parameter.get("maximum") is None
                and parameter.get("enum") is None
            ):
                findings.append(
                    _finding(
                        "Unbounded Pagination",
                        "MEDIUM",
                        (
                            f"{endpoint.get('method')} "
                            f"{endpoint.get('path')} parameter "
                            f"'{parameter.get('name')}' does not "
                            "document a maximum value."
                        ),
                    )
                )

        elif parameter_type in {"integer", "number"}:
            if (
                parameter.get("minimum") is None
                and parameter.get("maximum") is None
                and parameter.get("enum") is None
            ):
                findings.append(
                    _finding(
                        "Unbounded Numeric Input",
                        "MEDIUM",
                        (
                            f"{endpoint.get('method')} "
                            f"{endpoint.get('path')} numeric parameter "
                            f"'{parameter.get('name')}' has no documented "
                            "range constraint."
                        ),
                    )
                )

    return findings
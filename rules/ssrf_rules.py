"""Static SSRF indicators for normalized OpenAPI endpoints."""


URL_PARAMETER_NAMES = {
    "url",
    "uri",
    "callback",
    "webhook",
    "target",
    "redirect",
    "endpoint",
    "remote_url",
    "remote_uri",
}


def _finding(rule, severity, message):
    return {
        "rule": rule,
        "severity": severity,
        "message": message,
    }


def _check_parameter(parameter, endpoint):
    name = str(parameter.get("name", "")).lower()
    schema_format = str(
        parameter.get("format", "")
    ).lower()

    if (
        name in URL_PARAMETER_NAMES
        or schema_format in {"uri", "url"}
    ):
        return _finding(
            "Potential SSRF Input",
            "MEDIUM",
            (
                f"{endpoint.get('method')} "
                f"{endpoint.get('path')} accepts URL-like input "
                f"'{parameter.get('name')}' without documented "
                "SSRF protection or an allowlist."
            ),
        )

    return None


def _walk_schema(value, endpoint, findings):
    if isinstance(value, dict):

        properties = value.get("properties", {})

        if isinstance(properties, dict):
            for name, schema in properties.items():

                schema = schema if isinstance(schema, dict) else {}

                parameter = {
                    "name": name,
                    "format": schema.get("format"),
                }

                finding = _check_parameter(
                    parameter,
                    endpoint,
                )

                if finding:
                    findings.append(finding)

                _walk_schema(
                    schema,
                    endpoint,
                    findings,
                )

        for key, child in value.items():
            if key != "properties":
                _walk_schema(
                    child,
                    endpoint,
                    findings,
                )

    elif isinstance(value, list):
        for item in value:
            _walk_schema(
                item,
                endpoint,
                findings,
            )


def check_ssrf(endpoint):
    findings = []

    for parameter in endpoint.get(
        "parameters",
        [],
    ):
        finding = _check_parameter(
            parameter,
            endpoint,
        )

        if finding:
            findings.append(finding)

    request_body = endpoint.get(
        "request_body"
    )

    if request_body:
        _walk_schema(
            request_body.get(
                "content",
                {},
            ),
            endpoint,
            findings,
        )

    return findings
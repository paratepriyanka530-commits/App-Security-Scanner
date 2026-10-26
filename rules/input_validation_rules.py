"""Input-validation rules for normalized endpoint parameters."""


def check_input_validation(endpoint):
    findings = []
    for parameter in endpoint.get("parameters", []):
        name = parameter.get("name", "unknown")
        schema_type = parameter.get("type")
        if schema_type == "string":
            keys, detail = ("minLength", "maxLength", "pattern", "enum"), "length, pattern, or enum"
        elif schema_type in ("integer", "number"):
            keys, detail = ("minimum", "maximum", "enum"), "range or enum"
        else:
            continue
        if not any(parameter.get(key) is not None for key in keys):
            findings.append({"rule": "Missing Input Validation", "severity": "MEDIUM", "message": f"{schema_type.title()} parameter '{name}' has no {detail} validation."})
    return findings

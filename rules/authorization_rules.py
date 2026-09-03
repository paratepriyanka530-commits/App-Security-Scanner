"""Authorization rules using the ``x-required-roles`` OpenAPI extension."""


def check_authorization(endpoint):
    """Report operations marked role-protected without documented roles."""
    required_roles = endpoint.get("required_roles")
    if required_roles is None or required_roles:
        return []
    return [{
        "rule": "Missing Authorization",
        "severity": "HIGH",
        "message": (
            f"{endpoint.get('method')} {endpoint.get('path')} is marked as "
            "role-protected but does not define x-required-roles."
        ),
    }]

"""Compatibility facade and rule runner for the split rule modules."""

from .authentication_rules import (
    check_dangerous_method_security,
    check_missing_authentication,
    check_sensitive_data_exposure,
)
from .authorization_rules import check_authorization
from .input_validation_rules import check_input_validation
from .rate_limit_rules import check_rate_limiting
from .security_headers_rules import check_security_headers


def run_all_rules(endpoint):
    findings = []
    for rule in (
        check_missing_authentication,
        check_sensitive_data_exposure,
        check_authorization,
        check_input_validation,
        check_security_headers,
        check_rate_limiting,
        check_dangerous_method_security,
    ):
        findings.extend(rule(endpoint))
    return findings

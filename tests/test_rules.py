"""End-to-end rule tests against labelled OpenAPI dataset fixtures."""

import json
from pathlib import Path

from parser.openapi_parser import parse_openapi
from rules.security_rules import run_all_rules


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASETS = PROJECT_ROOT / "datasets"


def _rules_for_document(relative_path):
    document = parse_openapi(str(DATASETS / relative_path))
    return {
        finding["rule"]
        for endpoint in document["endpoints"]
        for finding in run_all_rules(endpoint)
    }


def test_labelled_datasets_match_expected_findings():
    labels = json.loads((DATASETS / "labels.json").read_text(encoding="utf-8"))
    for relative_path, expected_rules in labels.items():
        assert _rules_for_document(relative_path) == set(expected_rules)


def test_parser_preserves_validation_and_vendor_extensions():
    document = parse_openapi(str(DATASETS / "secure" / "secure_api_1.yaml"))
    parameter = document["endpoints"][0]["parameters"][0]
    assert parameter["minimum"] == 1
    assert parameter["maximum"] == 100000

    document = parse_openapi(str(DATASETS / "secure" / "secure_api_2.yaml"))
    endpoint = document["endpoints"][0]
    assert endpoint["rate_limit"] == 5
    assert endpoint["required_security_headers"] == ["Strict-Transport-Security"]


def test_authorization_rule_requires_a_documented_role():
    document = parse_openapi(str(DATASETS / "vulnerable" / "vulnerable_api_1.yaml"))
    findings = [
        finding["rule"]
        for endpoint in document["endpoints"]
        for finding in run_all_rules(endpoint)
    ]
    assert "Missing Authorization" in findings

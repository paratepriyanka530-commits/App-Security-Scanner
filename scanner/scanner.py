"""Orchestrate parsing and security-rule execution for every API endpoint."""

import argparse
import json
from pathlib import Path

from parser.openapi_parser import parse_openapi
from rules.security_rules import run_all_rules
from rules.api_inventory_rules import check_api_inventory
from rules.api_consumption_rules import check_api_consumption

from .finding import build_api_finding, build_finding
from .severity import highest_severity


def scan_endpoint(endpoint, endpoint_index=0):
    """Run all existing security rules against one normalized endpoint."""
    raw_findings = run_all_rules(endpoint)
    return [
        build_finding(raw, endpoint, endpoint_index, finding_index)
        for finding_index, raw in enumerate(raw_findings)
    ]


def _build_summary(endpoints, findings):
    by_severity = {}
    by_rule = {}
    for finding in findings:
        severity = finding["severity"]
        rule = finding["rule"]
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_rule[rule] = by_rule.get(rule, 0) + 1

    affected = {(item["method"], item["endpoint"]) for item in findings}
    return {
        "endpoints_scanned": len(endpoints),
        "affected_endpoints": len(affected),
        "total_findings": len(findings),
        "highest_severity": highest_severity(findings),
        "findings_by_severity": by_severity,
        "findings_by_rule": by_rule,
    }


def scan_parsed_api(parsed_api, source=None):
    """Scan a parser result and return a report-ready result dictionary."""
    if not isinstance(parsed_api, dict):
        raise TypeError("parsed_api must be the dictionary returned by parse_openapi")

    endpoints = parsed_api.get("endpoints", [])
    if not isinstance(endpoints, list):
        raise ValueError("parsed_api['endpoints'] must be a list")

    findings = []

    for endpoint_index, endpoint in enumerate(endpoints):
        findings.extend(scan_endpoint(endpoint, endpoint_index))

        api_findings = check_api_inventory(parsed_api)
        api_findings.extend(check_api_consumption(parsed_api))

        for finding_index, raw in enumerate(api_findings):
            findings.append(
                build_api_finding(
                    raw,
                    finding_index,
                )
            )

    return {
        "source": str(source) if source is not None else None,
        "api_info": parsed_api.get("api_info", {}),
        "summary": _build_summary(endpoints, findings),
        "findings": findings,
    }


def scan_file(file_path):
    """Parse and scan one OpenAPI YAML or JSON file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"OpenAPI file not found: {path}")
    return scan_parsed_api(parse_openapi(str(path)), source=path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan an OpenAPI contract")
    parser.add_argument("openapi_file", help="Path to an OpenAPI YAML or JSON file")
    args = parser.parse_args(argv)
    print(json.dumps(scan_file(args.openapi_file), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

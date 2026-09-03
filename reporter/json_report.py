import json
from pathlib import Path


def generate_json_report(findings, output_file):
    """
    Generate a JSON security scan report.

    Parameters:
        findings (list): List of vulnerability findings.
        output_file (str): Path where the report will be saved.
    """

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Low")
        if severity in severity_counts:
            severity_counts[severity] += 1

    unique_endpoints = set()

    for finding in findings:
        path = finding.get("path", "")
        method = finding.get("method", "")
        unique_endpoints.add(f"{method} {path}")

    report = {
        "scan_summary": {
            "total_endpoints": len(unique_endpoints),
            "total_findings": len(findings),
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"]
        },
        "findings": findings
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report


if __name__ == "__main__":

    input_file = "reports/sample_findings.json"
    output_file = "reports/report.json"

    with open(input_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    findings = data.get("findings", [])

    generate_json_report(findings, output_file)

    print(f"JSON report generated successfully: {output_file}")
    
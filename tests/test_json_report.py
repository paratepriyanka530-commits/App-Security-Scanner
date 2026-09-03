import json
from reporter.json_report import generate_json_report


def test_generate_json_report(tmp_path):

    findings = [
        {
            "path": "/users/{userId}",
            "method": "GET",
            "vulnerability": "Broken Object Level Authorization",
            "severity": "High",
            "confidence": 0.92,
            "description": "Unauthorized object access may be possible.",
            "evidence": "Object identifier is exposed.",
            "recommendation": "Verify object-level authorization."
        },
        {
            "path": "/users",
            "method": "POST",
            "vulnerability": "Missing Authentication",
            "severity": "Critical",
            "confidence": 0.95,
            "description": "Authentication is not defined.",
            "evidence": "No security requirement is specified.",
            "recommendation": "Require authentication."
        }
    ]

    output_file = tmp_path / "test_report.json"

    report = generate_json_report(
        findings,
        output_file
    )

    assert report["scan_summary"]["total_endpoints"] == 2
    assert report["scan_summary"]["total_findings"] == 2
    assert report["scan_summary"]["critical"] == 1
    assert report["scan_summary"]["high"] == 1

    assert len(report["findings"]) == 2

    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as file:
        saved_report = json.load(file)

    assert saved_report["scan_summary"]["total_findings"] == 2
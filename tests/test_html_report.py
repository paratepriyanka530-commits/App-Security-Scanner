import json
from reporter.html_report import generate_html_report


def test_generate_html_report(tmp_path):

    findings_file = "reports/sample_findings.json"

    with open(findings_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    findings = data["findings"]

    output_file = tmp_path / "test_report.html"

    generate_html_report(findings, output_file)

    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")

    assert "API Security Scan Report" in content
    assert "Broken Object Level Authorization" in content
    assert "Missing Authentication" in content
    assert "High" in content
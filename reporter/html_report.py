import json
from pathlib import Path
from html import escape


def generate_html_report(findings, output_file):
    """
    Generate an HTML security scan report.
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

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Security Scan Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}

        h1 {{
            text-align: center;
        }}

        .summary {{
            display: flex;
            gap: 15px;
            margin: 30px 0;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            flex: 1;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th, td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background-color: #333;
            color: white;
        }}

        .critical {{
            font-weight: bold;
        }}

        .high {{
            font-weight: bold;
        }}

        .medium {{
            font-weight: bold;
        }}

        .low {{
            font-weight: bold;
        }}
    </style>
</head>

<body>

<h1>API Security Scan Report</h1>

<div class="summary">

    <div class="card">
        <h3>Endpoints</h3>
        <p>{len(unique_endpoints)}</p>
    </div>

    <div class="card">
        <h3>Findings</h3>
        <p>{len(findings)}</p>
    </div>

    <div class="card">
        <h3>Critical</h3>
        <p>{severity_counts["Critical"]}</p>
    </div>

    <div class="card">
        <h3>High</h3>
        <p>{severity_counts["High"]}</p>
    </div>

    <div class="card">
        <h3>Medium</h3>
        <p>{severity_counts["Medium"]}</p>
    </div>

    <div class="card">
        <h3>Low</h3>
        <p>{severity_counts["Low"]}</p>
    </div>

</div>

<h2>Vulnerability Findings</h2>

<table>

<tr>
    <th>Vulnerability</th>
    <th>Endpoint</th>
    <th>Method</th>
    <th>Severity</th>
    <th>Confidence</th>
    <th>Description</th>
    <th>Evidence</th>
    <th>Recommendation</th>
</tr>
"""

    for finding in findings:

        severity = finding.get("severity", "Low")

        html += f"""
<tr>
    <td>{escape(str(finding.get("vulnerability", "Unknown")))}</td>

    <td>{escape(str(finding.get("path", "")))}</td>

    <td>{escape(str(finding.get("method", "")))}</td>

    <td class="{severity.lower()}">
        {escape(str(severity))}
    </td>

    <td>{escape(str(finding.get("confidence", "")))}</td>

    <td>{escape(str(finding.get("description", "")))}</td>

    <td>{escape(str(finding.get("evidence", "")))}</td>

    <td>{escape(str(finding.get("recommendation", "")))}</td>
</tr>
"""

    html += """
</table>

</body>
</html>
"""

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html)

    return html


if __name__ == "__main__":

    input_file = "reports/sample_findings.json"
    output_file = "reports/report.html"

    with open(input_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    findings = data.get("findings", [])

    generate_html_report(findings, output_file)

    print(f"HTML report generated successfully: {output_file}")
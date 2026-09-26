"""Convert raw rule results into report-ready scanner findings."""

from .severity import normalize_severity


RULE_METADATA = {
    "Missing Authentication": ("API2:2023 Broken Authentication", 0.95),
    "Missing Authorization": ("API1:2023 Broken Object Level Authorization", 0.90),
    "Dangerous Operation Without Security": (
        "API5:2023 Broken Function Level Authorization",
        0.95,
    ),
    "Sensitive Data Exposure": (
        "API3:2023 Broken Object Property Level Authorization",
        0.85,
    ),
    "Missing Input Validation": ("API8:2023 Security Misconfiguration", 0.85),
    "Missing Rate Limiting": ("API4:2023 Unrestricted Resource Consumption", 0.80),
    "Missing Security Header": ("API8:2023 Security Misconfiguration", 0.90),

    "Unbounded Pagination": (
        "API4:2023 Unrestricted Resource Consumption",
        0.80,
        ),
    "Unbounded Numeric Input": (
        "API4:2023 Unrestricted Resource Consumption",
        0.75,
        ),
    "Potential SSRF Input": (
        "API7:2023 Server Side Request Forgery",
         0.75,
        ),
}


def build_finding(raw_finding, endpoint, endpoint_index, finding_index):
    """Enrich one rule result while preserving the rule's original message."""
    rule = raw_finding.get("rule", "Unknown Rule")
    owasp_category, default_confidence = RULE_METADATA.get(
        rule, ("Unmapped", 0.50)
    )
    confidence = raw_finding.get("confidence", default_confidence)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = default_confidence
    confidence = round(min(1.0, max(0.0, confidence)), 2)

    return {
        "finding_id": f"F-{endpoint_index + 1:03d}-{finding_index + 1:02d}",
        "endpoint": endpoint.get("path"),
        "method": endpoint.get("method"),
        "rule": rule,
        "owasp_category": owasp_category,
        "severity": normalize_severity(raw_finding.get("severity")),
        "confidence": confidence,
        "evidence": raw_finding.get("message", "No evidence supplied by the rule."),
    }

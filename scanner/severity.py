"""Severity ordering and summary helpers for scanner findings."""

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def normalize_severity(value):
    """Return a supported uppercase severity, defaulting to INFO."""
    severity = str(value or "INFO").upper()
    return severity if severity in SEVERITY_ORDER else "INFO"


def highest_severity(findings):
    """Return the highest severity in an iterable of findings."""
    if not findings:
        return "NONE"
    return max(
        (normalize_severity(item.get("severity")) for item in findings),
        key=SEVERITY_ORDER.get,
    )

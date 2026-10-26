
import json
import tempfile
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st
from scanner.scanner import scan_file

st.set_page_config(
    page_title="SENTINEL | API Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# OBSIDIAN VIOLET THEME
# --------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #111116;
    --panel: #211D2A;
    --border: #302643;
    --violet: #9B7BFF;
    --violet-light: #B8A5FF;
    --text: #F3F0FA;
    --muted: #B7B0C7;
    --red: #FF858D;
    --amber: #E5A86A;
    --green: #65CDA0;
}

html, body, [class*="css"] {
    font-family: Inter, sans-serif;
}

.stApp {
    background: var(--bg);
    color: var(--text);
}

[data-testid="stHeader"] {
    background: rgba(17,17,22,.95);
}

[data-testid="stSidebar"] {
    background: #17151D;
    border-right: 1px solid var(--border);
}

.block-container {
    max-width: 1450px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* FORCE VIOLET SELECTED FILTER CHIPS */
.stMultiSelect [data-baseweb="tag"],
.stMultiSelect div[data-baseweb="tag"],
div[data-baseweb="select"] [data-baseweb="tag"] {
    background: #392C58 !important;
    background-color: #392C58 !important;
    border: 1px solid #8064D8 !important;
    box-shadow: none !important;
}

.stMultiSelect [data-baseweb="tag"] *,
div[data-baseweb="select"] [data-baseweb="tag"] * {
    color: #F3F0FA !important;
}

.stMultiSelect [data-baseweb="tag"] svg,
div[data-baseweb="select"] [data-baseweb="tag"] svg {
    fill: #B8A5FF !important;
    color: #B8A5FF !important;
}

[data-baseweb="tag"] {
    background-color: #392C58 !important;
    border-color: #8064D8 !important;
}

[data-baseweb="tag"] span {
    color: #F3F0FA !important;
}

[data-baseweb="tag"] svg {
    color: #B8A5FF !important;
    fill: #B8A5FF !important;
}

/* HERO */
.hero {
    background: linear-gradient(125deg, #211D2A, #191720 65%, #261F35);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 30px;
    margin-bottom: 25px;
}

.eyebrow {
    color: var(--violet-light);
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 2px;
    margin-bottom: 12px;
}

.hero-title {
    font-size: clamp(27px, 3vw, 39px);
    font-weight: 800;
    color: var(--text);
    margin: 0;
}

.hero-subtitle {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.8;
    margin-top: 12px;
}

.section-heading {
    color: var(--text);
    font-size: 21px;
    font-weight: 750;
    margin-top: 24px;
    margin-bottom: 5px;
}

.section-subtitle {
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 18px;
}

.metric-card {
    background: linear-gradient(145deg, #211D2A, #191720);
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 20px;
    min-height: 120px;
}

.metric-label {
    color: var(--muted);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .8px;
    text-transform: uppercase;
}

.metric-value {
    color: var(--text);
    font-size: 31px;
    font-weight: 800;
    margin-top: 10px;
}

.metric-note {
    color: #898198;
    font-size: 12px;
    margin-top: 6px;
}

div.stButton > button[kind="primary"] {
    background: var(--violet);
    color: #17131F;
    border: 1px solid var(--violet);
    border-radius: 10px;
    min-height: 44px;
    font-weight: 750;
}

div.stButton > button[kind="primary"]:hover {
    background: #B09AFF;
    border-color: #B09AFF;
}

div.stDownloadButton > button {
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 10px;
    min-height: 42px;
}

div.stDownloadButton > button:hover {
    border-color: var(--violet);
    color: var(--violet-light);
}

div[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
}

div[data-testid="stMetric"] {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
}

div[data-testid="stExpander"] {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
}

div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div {
    border-color: var(--border);
}

hr {
    border-color: var(--border);
}

.footer {
    color: #898198;
    font-size: 11px;
    text-align: center;
    border-top: 1px solid var(--border);
    padding-top: 20px;
    margin-top: 35px;
    line-height: 1.9;
}
</style>
""", unsafe_allow_html=True)


def confidence_text(value):
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return "N/A"


def remediation(finding):
    rule = finding.get("rule", "")
    guidance = {
        "Missing Authentication":
            "Review the intended access policy and enforce authentication "
            "where required. Check inherited OpenAPI security requirements first.",
        "Sensitive Data Exposure":
            "Review response schemas and remove or protect sensitive fields. "
            "Verify property-level authorization at runtime.",
        "Missing Input Validation":
            "Add appropriate schema constraints and validate inputs at runtime.",
        "Dangerous Operation Without Security":
            "Review the intended access policy. Public operations such as login "
            "may intentionally be unauthenticated.",
        "Missing Rate Limiting":
            "Define and enforce rate limits, especially for login and "
            "resource-intensive operations.",
        "Missing Security Headers":
            "Review gateway, server, and proxy configuration for suitable "
            "security headers.",
    }
    return guidance.get(
        rule,
        "Review the API design and verify the required controls against "
        "the actual implementation."
    )


def severity_colour(severity):
    return {
        "CRITICAL": "#FF858D",
        "HIGH": "#FF858D",
        "MEDIUM": "#E5A86A",
        "LOW": "#65CDA0",
    }.get(str(severity).upper(), "#B7B0C7")


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ SENTINEL")
    st.caption("API SECURITY INTELLIGENCE")
    st.divider()

    page = st.radio(
        "Workspace",
        ["Security Dashboard", "Scan Reports", "Static Rule Engine"],
    )

    st.divider()
    st.markdown("### Analysis Pipeline")
    st.markdown("① OpenAPI Upload")
    st.markdown("② Parser & Normalizer")
    st.markdown("③ Static Security Rules")
    st.markdown("④ Findings & Reports")
    st.divider()
    st.markdown(
        '<span style="color:#65CDA0">● STATIC ENGINE AVAILABLE</span>',
        unsafe_allow_html=True,
    )
    st.caption("LLM, RAG and cross-validation are not connected yet.")


# --------------------------------------------------
# HEADER
# --------------------------------------------------
st.markdown("""
<div class="hero">
    <div class="eyebrow">APPLICATION SECURITY · OPENAPI ANALYSIS</div>
    <h1 class="hero-title">API Security Intelligence</h1>
    <div class="hero-subtitle">
        Inspect REST API specifications, investigate OWASP-mapped findings,
        and export reports from one unified workspace.
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="section-heading">01 / Scan an API</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="section-subtitle">Upload an OpenAPI 3.0/3.1 YAML or JSON specification.</div>',
    unsafe_allow_html=True,
)

uploaded = st.file_uploader(
    "Choose API specification",
    type=["yaml", "yml", "json"],
)

c1, c2 = st.columns([1, 2])
with c1:
    scan_clicked = st.button(
        "🔍 Analyze API Specification",
        type="primary",
        use_container_width=True,
        disabled=uploaded is None,
    )
with c2:
    if uploaded:
        st.caption(f"Selected: {uploaded.name} · {uploaded.size / 1024:.1f} KB")
    else:
        st.caption("No specification selected.")

if scan_clicked and uploaded is not None:
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=Path(uploaded.name).suffix.lower(),
            delete=False,
        ) as temp:
            temp.write(uploaded.getvalue())
            temp_path = temp.name

        with st.spinner("Parsing API and running static security rules..."):
            result = scan_file(temp_path)

        result["scan_timestamp"] = datetime.now().strftime(
            "%d %b %Y, %I:%M:%S %p"
        )
        st.session_state["scan_result"] = result
        st.session_state["scan_filename"] = uploaded.name
        st.success("Analysis completed successfully.")
    except Exception as error:
        st.error(f"Unable to scan this specification: {error}")
    finally:
        if temp_path and Path(temp_path).exists():
            Path(temp_path).unlink()

result = st.session_state.get("scan_result")

if result is None:
    st.info("Upload a specification and click **Analyze API Specification** to begin.")
    st.markdown("""
    <div class="footer">
        SENTINEL · API SECURITY INTELLIGENCE<br>
        Specification-level analysis powered by the existing Python scanner.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

summary = result.get("summary", {}) or {}
findings = result.get("findings", []) or []
api_info = result.get("api_info", {}) or {}
severity_counts = summary.get("findings_by_severity", {}) or {}
filename = st.session_state.get("scan_filename", "API specification")

high = severity_counts.get("HIGH", 0) + severity_counts.get("CRITICAL", 0)
medium = severity_counts.get("MEDIUM", 0)
low = severity_counts.get("LOW", 0)
total = summary.get("total_findings", len(findings))
endpoints = summary.get("endpoints_scanned", 0)
affected = summary.get("affected_endpoints", 0)

# --------------------------------------------------
# API OVERVIEW
# --------------------------------------------------
st.divider()
st.markdown(
    '<div class="section-heading">02 / API Overview</div>',
    unsafe_allow_html=True,
)
a, b, c = st.columns(3)
with a:
    st.markdown("**API TITLE**")
    st.write(api_info.get("title") or "Unknown")
with b:
    st.markdown("**API VERSION**")
    st.write(api_info.get("version") or "Unknown")
with c:
    st.markdown("**OPENAPI VERSION**")
    st.write(api_info.get("openapi_version") or "Unknown")

st.caption(
    f"Last scan: {result.get('scan_timestamp', 'Unavailable')} · File: {filename}"
)

# --------------------------------------------------
# SECURITY METRICS
# --------------------------------------------------
st.markdown(
    '<div class="section-heading">03 / Security Posture</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="section-subtitle">Potential risks identified by current static rules.</div>',
    unsafe_allow_html=True,
)

cols = st.columns(4)
metrics = [
    ("Endpoints Scanned", endpoints, "Operations analyzed", "#F3F0FA"),
    ("High / Critical", high, "Prioritize manual review", "#FF858D"),
    ("Medium Severity", medium, "Potential design weaknesses", "#E5A86A"),
    ("Total Findings", total, f"{affected} affected endpoints", "#B8A5FF"),
]
for col, (label, value, note, colour) in zip(cols, metrics):
    with col:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-label">{label}</div>'
            f'<div class="metric-value" style="color:{colour}">{value}</div>'
            f'<div class="metric-note">{note}</div></div>',
            unsafe_allow_html=True,
        )

# --------------------------------------------------
# ANALYTICS
# --------------------------------------------------
st.divider()
st.markdown(
    '<div class="section-heading">04 / Findings Analytics</div>',
    unsafe_allow_html=True,
)
chart_col, summary_col = st.columns([1.2, 1])

with chart_col:
    st.markdown("#### Severity Distribution")
    chart = pd.DataFrame({
        "Severity": ["HIGH / CRITICAL", "MEDIUM", "LOW"],
        "Findings": [high, medium, low],
    }).set_index("Severity")
    if total:
        st.bar_chart(chart, color="#9B7BFF", use_container_width=True)
    else:
        st.success("No findings detected by the current static rules.")

with summary_col:
    st.markdown("#### Scan Summary")
    st.metric("Affected Endpoints", affected)
    st.metric("Highest Severity", summary.get("highest_severity") or "None")
    st.caption(
        "Severity and confidence are rule-generated estimates, not runtime "
        "exploitability measurements."
    )

# --------------------------------------------------
# FINDINGS EXPLORER
# --------------------------------------------------
st.divider()
st.markdown(
    '<div class="section-heading">05 / Security Findings</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="section-subtitle">Filter findings, review evidence, and inspect suggested remediation.</div>',
    unsafe_allow_html=True,
)

if findings:
    f1, f2 = st.columns(2)
    severities = sorted({
        str(x.get("severity", "UNKNOWN")).upper() for x in findings
    })
    endpoints_available = sorted({
        str(x.get("endpoint", "")) for x in findings
    })

    with f1:
        selected_severities = st.multiselect(
            "Filter by severity",
            severities,
            default=severities,
            key="severity_filter",
        )
    with f2:
        selected_endpoints = st.multiselect(
            "Filter by endpoint",
            endpoints_available,
            default=endpoints_available,
            key="endpoint_filter",
        )

    filtered = [
        x for x in findings
        if str(x.get("severity", "UNKNOWN")).upper() in selected_severities
        and str(x.get("endpoint", "")) in selected_endpoints
    ]

    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

    rows = [{
        "Finding ID": x.get("finding_id", ""),
        "Method": x.get("method", ""),
        "Endpoint": x.get("endpoint", ""),
        "Rule": x.get("rule", ""),
        "OWASP Category": x.get("owasp_category", ""),
        "Severity": str(x.get("severity", "")).upper(),
        "Confidence": confidence_text(x.get("confidence")),
    } for x in filtered]

    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("#### Finding Details")
    if filtered:
        options = {
            f"{x.get('finding_id', 'Finding')} · "
            f"{x.get('method', '')} {x.get('endpoint', '')} · "
            f"{x.get('rule', 'Security finding')}": x
            for x in filtered
        }
        label = st.selectbox("Select a finding to inspect", list(options))
        item = options[label]
        severity = str(item.get("severity", "UNKNOWN")).upper()
        colour = severity_colour(severity)

        st.markdown(
            f'<div class="metric-card" style="min-height:unset;margin-top:10px">'
            f'<div class="metric-label" style="color:#B8A5FF">SELECTED FINDING</div>'
            f'<div style="font-size:23px;font-weight:800;margin-top:9px">'
            f'{item.get("rule", "Security finding")}</div>'
            f'<div style="color:#B7B0C7;margin-top:7px">'
            f'{item.get("method", "")} {item.get("endpoint", "")}</div>'
            f'<div style="display:inline-block;margin-top:14px;padding:6px 10px;'
            f'border:1px solid {colour};border-radius:8px;color:{colour};'
            f'font-size:12px;font-weight:800">{severity} SEVERITY</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        d1, d2, d3 = st.columns(3)
        d1.metric("Confidence", confidence_text(item.get("confidence")))
        d2.metric("Finding ID", item.get("finding_id", "N/A"))
        d3.metric("HTTP Method", item.get("method", "N/A"))

        st.markdown("**OWASP Category**")
        st.write(item.get("owasp_category") or "Not specified")

        st.markdown("**Evidence**")
        st.info(str(item.get("evidence") or "No evidence supplied."))

        st.markdown("**Suggested Remediation**")
        st.success(remediation(item))

        with st.expander("Interpretation and validation notes"):
            st.write(
                "This is a potential risk inferred from the API specification. "
                "Check inherited security requirements, intended public access, "
                "and actual server-side controls before treating it as a confirmed vulnerability."
            )
    else:
        st.info("No findings match the selected filters.")
else:
    st.success("No findings detected by the current static rules.")

# --------------------------------------------------
# REPORT EXPORTS
# --------------------------------------------------
st.divider()
st.markdown(
    '<div class="section-heading">06 / Reports & Export</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="section-subtitle">Download scan results for documentation and analysis.</div>',
    unsafe_allow_html=True,
)

json_report = json.dumps(result, indent=2, ensure_ascii=False)
csv_rows = [{
    "Finding ID": x.get("finding_id", ""),
    "Method": x.get("method", ""),
    "Endpoint": x.get("endpoint", ""),
    "Rule": x.get("rule", ""),
    "OWASP Category": x.get("owasp_category", ""),
    "Severity": x.get("severity", ""),
    "Confidence": x.get("confidence", ""),
    "Evidence": x.get("evidence", ""),
} for x in findings]

csv_report = pd.DataFrame(csv_rows, columns=[
    "Finding ID", "Method", "Endpoint", "Rule",
    "OWASP Category", "Severity", "Confidence", "Evidence",
]).to_csv(index=False)

x1, x2 = st.columns(2)
with x1:
    st.download_button(
        "⬇️ Download JSON Report",
        json_report,
        file_name="api_security_report.json",
        mime="application/json",
        use_container_width=True,
    )
with x2:
    st.download_button(
        "📄 Download CSV Report",
        csv_report,
        file_name="api_security_report.csv",
        mime="text/csv",
        use_container_width=True,
    )

# --------------------------------------------------
# SIDEBAR PAGE INFORMATION
# --------------------------------------------------
if page == "Scan Reports":
    st.divider()
    st.markdown("### Report Summary")
    st.json({
        "Source file": filename,
        "Scan timestamp": result.get("scan_timestamp"),
        "API title": api_info.get("title"),
        "Endpoints scanned": endpoints,
        "Affected endpoints": affected,
        "Total findings": total,
        "Highest severity": summary.get("highest_severity"),
    })

elif page == "Static Rule Engine":
    st.divider()
    st.markdown("### Static Rule Engine")
    st.dataframe(pd.DataFrame([
        ["Authentication", "Existing static rules"],
        ["Sensitive data exposure", "Existing static rules"],
        ["Authorization", "Existing static rules"],
        ["Input validation", "Existing static rules"],
        ["Rate limiting", "Existing static rules"],
        ["Security headers", "Existing static rules"],
        ["Dangerous HTTP methods", "Existing static rules"],
        ["LLM semantic analysis", "Not connected"],
        ["RAG retrieval", "Not connected"],
        ["Cross-validation", "Not connected"],
    ], columns=["Component", "Status"]), hide_index=True, use_container_width=True)

st.markdown("""
<div class="footer">
<strong>SENTINEL · API SECURITY INTELLIGENCE</strong><br>
OpenAPI specification analysis · OWASP-mapped static rules<br>
Current implementation: parser + static security rules + report export.<br>
LLM analysis, RAG and cross-validation are not yet connected.<br>
Findings indicate potential specification-level risks, not confirmed
vulnerabilities in a running API.
</div>
""", unsafe_allow_html=True)

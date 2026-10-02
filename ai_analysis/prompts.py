"""Prompts for specification-level semantic security analysis."""

import json

from ai_analysis.knowledge.models import VulnerabilityPattern


_CONTEXT_KEYS = (
    "api",
    "endpoint",
    "security",
    "parameters",
    "request_body",
    "responses",
)


def build_security_analysis_prompt(
    context: dict,
    retrieved_knowledge: list[VulnerabilityPattern] | None = None,
) -> str:
    """Build a strict JSON-only semantic analysis prompt for one endpoint."""
    if not isinstance(context, dict):
        raise TypeError("context must be a dictionary")
    if not context:
        raise ValueError("context must not be empty")
    if retrieved_knowledge is not None:
        if not isinstance(retrieved_knowledge, list):
            raise TypeError("retrieved_knowledge must be a list")
        if any(
            not isinstance(entry, VulnerabilityPattern)
            for entry in retrieved_knowledge
        ):
            raise TypeError(
                "retrieved_knowledge must contain VulnerabilityPattern objects"
            )

    # Only the public context-builder contract is allowed into the prompt.
    # In particular, unrelated/static-analysis fields are intentionally omitted.
    analysis_context = {
        key: context[key]
        for key in _CONTEXT_KEYS
        if key in context
    }
    serialized_context = json.dumps(analysis_context, indent=2)

    knowledge_section = ""
    if retrieved_knowledge is not None:
        similar_patterns = [
            {
                "source_project": pattern.source_project,
                "source_reference": pattern.source_reference,
                "title": pattern.title,
                "owasp_category": pattern.owasp_category,
                "api_shape": pattern.api_shape.model_dump(),
                "semantic_context": pattern.semantic_context,
                "vulnerability_pattern": pattern.vulnerability_pattern,
                "security_reasoning": pattern.security_reasoning,
                "limitations": pattern.limitations,
            }
            for pattern in retrieved_knowledge
        ]
        knowledge_section = f"""
Retrieved similar vulnerable API patterns:
{json.dumps(similar_patterns, indent=2)}

These retrieved patterns are examples, not proof that the current API is vulnerable. Compare the current API semantically with each pattern and identify both meaningful similarities and important differences. Report a vulnerability only when evidence in the current API context supports it. Do not copy a vulnerability merely because a similar pattern was retrieved. Use OWASP category metadata only when supported by current evidence, and do not infer or claim runtime exploitability.
"""

    return f"""You are performing semantic security analysis of one endpoint from an OpenAPI specification.

Scope and evidence rules:
- Identify only potential, specification-level security risks. Do not claim that a vulnerability is runtime-exploitable or proven in a deployed system.
- Use only evidence present in the supplied API context. Do not assume implementation details, runtime behavior, data flows, or controls that are not documented.
- Reduce confidence when the specification is ambiguous or evidence is incomplete.
- If evidence is insufficient, do not invent a vulnerability; return SAFE with an empty findings list.
- No static-rule results are provided. Keep this analysis independent from static analysis and do not recreate mechanical static checks.
- The absence of a documented control is context to reason about, not automatic proof of a vulnerability.

Consider the OWASP API Security Top 10 2023 where the supplied specification contains relevant semantic evidence. Not every category can necessarily be assessed from OpenAPI alone:
- API1 Broken Object Level Authorization
- API2 Broken Authentication
- API3 Broken Object Property Level Authorization
- API4 Unrestricted Resource Consumption
- API5 Broken Function Level Authorization
- API6 Unrestricted Access to Sensitive Business Flows
- API7 Server-Side Request Forgery
- API8 Security Misconfiguration
- API9 Improper Inventory Management
- API10 Unsafe Consumption of APIs

Prioritize contextual reasoning such as caller-controlled object identifiers and ownership, sensitive fields relative to operation intent, role or scope inconsistencies, sensitive business flows, URL parameters that may be server-fetched, trust relationships across operations, and security-sensitive operation descriptions. Do not turn these considerations into assumptions.
{knowledge_section}

Return JSON only, with no Markdown, commentary, or additional keys, using this exact shape:
{{
  "endpoint": "...",
  "method": "...",
  "status": "SAFE" or "POTENTIAL_VULNERABILITY",
  "findings": [
    {{
      "endpoint": "...",
      "method": "...",
      "rule": "...",
      "owasp_category": "...",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "confidence": 0.0,
      "evidence": "...",
      "detected_by": "AI"
    }}
  ]
}}

When status is SAFE, findings must be []. When status is POTENTIAL_VULNERABILITY, include at least one evidence-supported finding. Every finding must use the same endpoint and method as the enclosing result.

API context:
{serialized_context}
"""

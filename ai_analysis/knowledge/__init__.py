"""Curated security knowledge for semantic API analysis."""

from ai_analysis.knowledge.models import APIShape, KnowledgeEntry, VulnerabilityPattern
from ai_analysis.knowledge.owasp_knowledge import OWASP_API_TOP_10_KNOWLEDGE
from ai_analysis.knowledge.vulnerability_patterns import VULNERABILITY_PATTERNS

__all__ = [
    "APIShape",
    "KnowledgeEntry",
    "OWASP_API_TOP_10_KNOWLEDGE",
    "VULNERABILITY_PATTERNS",
    "VulnerabilityPattern",
]

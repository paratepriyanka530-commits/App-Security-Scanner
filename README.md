# AI-Driven API Security Scanner

## Project Overview

AI-Driven API Security Scanner is a security analysis system designed to detect OWASP-style vulnerabilities in REST API specifications.

The system analyzes OpenAPI specifications and combines deterministic static security rules with Large Language Model (LLM) based semantic analysis and Retrieval-Augmented Generation (RAG).

The goal is to identify security weaknesses at the API contract level and provide explainable, severity-ranked findings and remediation guidance.

## Project Title

**AI-Driven API Security Scanner: A Hybrid Static and Large-Language-Model Approach for Detecting OWASP-Style Vulnerabilities in REST API Specifications (OpenAPI 3.0/3.1)**

## Objectives

- Parse OpenAPI 3.0/3.1 specifications.
- Extract and normalize API endpoints, methods, parameters, request bodies, responses, and security information.
- Resolve local `$ref` references.
- Detect high-confidence API security vulnerabilities using static security rules.
- Use LLM and RAG-based analysis for complex semantic security issues.
- Generate explainable security findings with severity and confidence information.
- Evaluate scanner performance using metrics such as Precision, Recall, F1-score, and False Positive Rate.

## System Workflow

```text
OpenAPI Specification
        ↓
Parser & Normalizer
        ↓
Static Security Rules
        ↓
AI / LLM Semantic Analyzer
        ↓
RAG Knowledge Base
        ↓
Security Findings
        ↓
Report Generation

## Person 1 — OpenAPI Parser & Security Rules

### OpenAPI Parser

The parser accepts OpenAPI YAML and JSON specifications and supports:

- OpenAPI 3.0 and 3.1
- API metadata extraction
- Endpoint and HTTP method extraction
- Path-level and operation-level parameters
- Request body extraction
- Response extraction
- Security scheme extraction
- Local `$ref` resolution
- Operation-level parameter overrides

### Implemented Security Rules

The security-rule layer performs static analysis of normalized OpenAPI endpoints.

| OWASP API Security Category | Implemented Check |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

### API4 — Resource Consumption

Static checks include:

- Unbounded pagination parameters
- Unbounded numeric parameters

### API7 — SSRF

Detects URL-like inputs such as:

- `url`
- `uri`
- `callback`
- `webhook`
- `target`
- `redirect`
- URI/URL schema formats

### API9 — Improper Inventory Management

Checks for missing:

- API title
- API version
- OpenAPI version
- Documented endpoints

### API10 — Unsafe Consumption of APIs

Detects request-body properties that accept URI/URL values without documented validation or allowlist controls.

### Finding Format

Each scanner finding contains:

- Finding ID
- Endpoint
- HTTP method
- Security rule
- OWASP category
- Severity
- Confidence
- Evidence

### Testing

Current test suite:

**44 tests passed**

The scanner has been verified against vulnerable and secure OpenAPI datasets.
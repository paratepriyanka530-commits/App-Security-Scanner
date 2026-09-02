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
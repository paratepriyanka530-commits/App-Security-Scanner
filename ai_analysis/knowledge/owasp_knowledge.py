"""Curated OWASP API Security Top 10 2023 semantic knowledge."""

from ai_analysis.knowledge.models import KnowledgeEntry


OWASP_API_TOP_10_KNOWLEDGE: tuple[KnowledgeEntry, ...] = (
    KnowledgeEntry(
        id="API1-object-authorization",
        owasp_category="API1:2023 Broken Object Level Authorization",
        title="Object-level authorization for caller-selected resources",
        description=(
            "Object identifiers supplied by a caller can require authorization "
            "that verifies access to the specific selected object."
        ),
        semantic_indicators=[
            "caller-controlled object ID or user ID in a path or parameter",
            "read, update, or delete operation for one account, order, document, or user",
            "ownership or tenant boundary implied by the operation intent",
        ],
        specification_evidence=[
            "path and query parameter names",
            "operation summary and description",
            "documented security scopes and ownership semantics",
        ],
        limitations=[
            "OpenAPI cannot prove whether runtime object-level authorization is enforced.",
        ],
        example_patterns=[
            "GET /users/{userId}",
            "DELETE /orders/{orderId} selected by a caller-controlled identifier",
        ],
    ),
    KnowledgeEntry(
        id="API2-authentication-semantics",
        owasp_category="API2:2023 Broken Authentication",
        title="Authentication and credential lifecycle semantics",
        description=(
            "Authentication endpoints and credential or token flows require coherent "
            "identity verification, issuance, recovery, and revocation semantics."
        ),
        semantic_indicators=[
            "login, token, password reset, recovery, or multi-factor operation",
            "credentials or authentication tokens in request or response properties",
            "inconsistent authentication requirements across identity operations",
        ],
        specification_evidence=[
            "security schemes and operation security requirements",
            "credential-related request and response schemas",
            "authentication operation descriptions",
        ],
        limitations=[
            "Token validation, password verification, brute-force controls, and session handling are primarily runtime behavior.",
        ],
        example_patterns=[
            "POST /login with username and password",
            "token refresh or password recovery endpoint",
        ],
    ),
    KnowledgeEntry(
        id="API3-property-authorization",
        owasp_category="API3:2023 Broken Object Property Level Authorization",
        title="Sensitive object properties in requests and responses",
        description=(
            "Property-level authorization concerns arise when clients can read or "
            "modify sensitive object fields beyond the operation's intended purpose."
        ),
        semantic_indicators=[
            "password, credential, secret, token, role, privilege, or internal field",
            "sensitive response properties unrelated to the operation intent",
            "client-writable administrative or ownership properties",
        ],
        specification_evidence=[
            "request-body property names and readOnly or writeOnly metadata",
            "response schema property names",
            "operation summary and description",
        ],
        limitations=[
            "OpenAPI cannot prove which properties are returned, accepted, or authorized at runtime.",
        ],
        example_patterns=[
            "GET /users response includes a password field",
            "profile update accepts role, isAdmin, ownerId, or accountBalance",
        ],
    ),
    KnowledgeEntry(
        id="API4-resource-consumption",
        owasp_category="API4:2023 Unrestricted Resource Consumption",
        title="Resource-intensive operations and consumption bounds",
        description=(
            "Operations that consume compute, storage, bandwidth, or paid downstream "
            "services may need documented bounds and abuse controls."
        ),
        semantic_indicators=[
            "unbounded page size, upload size, batch size, or result count",
            "expensive report, export, search, image, email, SMS, or biometric operation",
            "rate-limit or quota metadata relevant to costly work",
        ],
        specification_evidence=[
            "numeric parameter bounds and pagination metadata",
            "request-body size and array constraints",
            "rate-limit metadata and operation descriptions",
        ],
        limitations=[
            "Actual resource cost, capacity, caching, and runtime throttling are not established by OpenAPI alone.",
        ],
        example_patterns=[
            "large unbounded limit parameter",
            "bulk export, file upload, SMS send, or report generation",
        ],
    ),
    KnowledgeEntry(
        id="API5-function-authorization",
        owasp_category="API5:2023 Broken Function Level Authorization",
        title="Role and scope boundaries for privileged functions",
        description=(
            "Administrative or privileged operations require function-level access "
            "consistent with documented roles, scopes, and endpoint purpose."
        ),
        semantic_indicators=[
            "admin, moderation, approval, role management, or privileged operation",
            "role or scope mismatch between similar operations",
            "state-changing function exposed with unclear privilege requirements",
        ],
        specification_evidence=[
            "required roles and OAuth scopes",
            "path, method, summary, and description",
            "security requirement differences across related operations",
        ],
        limitations=[
            "OpenAPI declarations cannot prove that function-level authorization is enforced at runtime.",
        ],
        example_patterns=[
            "DELETE /admin/users/{id} without a documented admin role",
            "approval operation with scopes inconsistent with other privileged functions",
        ],
    ),
    KnowledgeEntry(
        id="API6-sensitive-business-flow",
        owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows",
        title="Automatable sensitive business flows",
        description=(
            "High-value business actions can be harmed through excessive automated use "
            "even when each individual request is otherwise valid."
        ),
        semantic_indicators=[
            "purchase, checkout, coupon, reservation, ticket, signup, referral, or comment flow",
            "inventory capture, promotion abuse, spam, scalping, or repeated account creation",
            "business action whose abuse depends on automation volume or frequency",
        ],
        specification_evidence=[
            "operation purpose in summaries and descriptions",
            "business-action request properties",
            "rate-limit, quota, or anti-automation metadata",
        ],
        limitations=[
            "Business impact, legitimate usage patterns, and effective anti-automation controls usually require runtime and domain evidence.",
        ],
        example_patterns=[
            "repeated coupon purchase or redemption",
            "automated signup, ticket purchase, reservation, or referral flow abuse",
        ],
    ),
    KnowledgeEntry(
        id="API7-server-side-request-forgery",
        owasp_category="API7:2023 Server Side Request Forgery",
        title="Server-side fetching of caller-supplied URLs",
        description=(
            "An operation may create SSRF exposure when the server fetches a remote "
            "resource selected through caller-controlled URL or URI input."
        ),
        semantic_indicators=[
            "URL, URI, callback, webhook, redirect, destination, host, or external server parameter",
            "import, preview, fetch, proxy, download, or callback-testing operation",
            "description indicating that the server retrieves a supplied location",
        ],
        specification_evidence=[
            "URL-formatted parameter and request property names",
            "URI format constraints and allow-list descriptions",
            "operation summaries describing remote fetch behavior",
        ],
        limitations=[
            "A URL parameter alone does not prove server-side fetching or missing destination validation.",
        ],
        example_patterns=[
            "POST /fetch with caller supplied url",
            "webhook callback URL or external server preview request",
        ],
    ),
    KnowledgeEntry(
        id="API8-security-configuration",
        owasp_category="API8:2023 Security Misconfiguration",
        title="Specification-visible security configuration concerns",
        description=(
            "Security configuration concerns can include unsafe protocol declarations, "
            "overly permissive cross-origin behavior, debug exposure, or missing hardening metadata."
        ),
        semantic_indicators=[
            "debug or diagnostic endpoint exposed in a production-facing API",
            "insecure HTTP server declaration or permissive cross-origin description",
            "security-related headers or configuration explicitly documented as disabled",
        ],
        specification_evidence=[
            "server URLs and environment descriptions",
            "security headers and configuration extensions",
            "debug, diagnostics, or error response documentation",
        ],
        limitations=[
            "Most platform, TLS, header, middleware, and deployment configuration is outside the OpenAPI document.",
        ],
        example_patterns=[
            "production server declared with plain HTTP",
            "debug endpoint or verbose diagnostic response",
        ],
    ),
    KnowledgeEntry(
        id="API9-api-inventory",
        owasp_category="API9:2023 Improper Inventory Management",
        title="API versions, environments, and deprecated inventory",
        description=(
            "Accurate inventories help prevent forgotten, deprecated, beta, or alternate "
            "API versions and hosts from remaining exposed."
        ),
        semantic_indicators=[
            "deprecated, legacy, beta, internal, test, staging, or old API version",
            "multiple versions or environment hosts with inconsistent documentation",
            "debug or undocumented-looking paths indicating inventory drift",
        ],
        specification_evidence=[
            "API version and deprecation metadata",
            "server URLs, descriptions, and path versioning",
            "operation tags and documentation completeness",
        ],
        limitations=[
            "One specification cannot reveal unknown deployments, shadow APIs, or hosts absent from the document.",
        ],
        example_patterns=[
            "/v1/legacy or /beta endpoint marked deprecated",
            "production and staging server URLs mixed in one public specification",
        ],
    ),
    KnowledgeEntry(
        id="API10-unsafe-api-consumption",
        owasp_category="API10:2023 Unsafe Consumption of APIs",
        title="Trust boundaries with third-party and downstream APIs",
        description=(
            "An API may rely on data or behavior from third-party services and should not "
            "implicitly trust downstream responses, redirects, or callbacks."
        ),
        semantic_indicators=[
            "third-party API, partner service, external provider, webhook, or callback integration",
            "downstream response data used by the operation",
            "external service trust, redirect, or data-validation semantics",
        ],
        specification_evidence=[
            "operation descriptions naming external dependencies",
            "callback and webhook definitions",
            "schemas representing third-party data or downstream responses",
        ],
        limitations=[
            "OpenAPI rarely shows downstream validation, redirect handling, transport controls, or third-party trust decisions.",
        ],
        example_patterns=[
            "payment or identity operation consuming a partner API response",
            "webhook event trusted as authoritative third-party data",
        ],
    ),
)

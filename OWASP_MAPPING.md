# OWASP API Security Rule Mapping

This scanner statically analyzes OpenAPI contracts. A finding means the
document lacks evidence of a control; it does not prove the deployed service
is vulnerable.

| Scanner rule | OWASP API Security Top 10 (2023) area | Contract evidence checked |
| --- | --- | --- |
| Missing Authentication | API2: Broken Authentication | `security` on sensitive paths |
| Missing Authorization | API1: Broken Object Level Authorization | `x-required-roles` on role-protected operations |
| Dangerous Operation Without Security | API1 / API5: Broken Function Level Authorization | `security` on state-changing operations |
| Sensitive Data Exposure | API3: Broken Object Property Level Authorization | sensitive response-schema fields |
| Missing Input Validation | API8: Security Misconfiguration | parameter range, pattern, enum, and length constraints |
| Missing Rate Limiting | API4: Unrestricted Resource Consumption | `x-rate-limit` on authentication-sensitive operations |
| Missing Security Header | API8: Security Misconfiguration | headers required by `x-required-security-headers` |

## Contract conventions

Some runtime controls are not represented in standard OpenAPI, so this project
uses these vendor extensions:

```yaml
x-rate-limit: 5
x-required-security-headers:
  - Strict-Transport-Security
x-required-roles:
  - admin
```

Use `x-required-roles: []` only in intentionally vulnerable fixtures. A real
role-protected operation should declare one or more permitted roles. Runtime
authorization enforcement still needs application-level tests.

## Reference

The categories follow the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

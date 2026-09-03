# API Security Scanner - Test Results

## Testing Summary

The complete API Security Scanner was tested using vulnerable and secure OpenAPI specifications.

| Dataset | Expected | Detected | Result |
|---|---:|---:|---|
| vulnerable_api_1.yaml | 6 vulnerability types | 6 vulnerability types | PASS |
| vulnerable_api_2.yaml | 2 vulnerability types | 2 vulnerability types | PASS |
| secure_api_1.yaml | 0 vulnerabilities | 0 vulnerabilities | PASS |
| secure_api_2.yaml | 0 vulnerabilities | 0 vulnerabilities | PASS |

## Vulnerable API 1

Expected vulnerabilities:
- Dangerous Operation Without Security
- Missing Authentication
- Missing Authorization
- Missing Input Validation
- Missing Security Header
- Sensitive Data Exposure

Detected:
- Dangerous Operation Without Security
- Missing Authentication
- Missing Authorization
- Missing Input Validation
- Missing Security Header
- Sensitive Data Exposure

Total findings detected: 7

Result: PASS

## Vulnerable API 2

Expected vulnerabilities:
- Dangerous Operation Without Security
- Missing Rate Limiting

Detected:
- Dangerous Operation Without Security
- Missing Rate Limiting

Total findings detected: 2

Result: PASS

## Secure APIs

Both secure API datasets produced zero findings as expected.

- secure_api_1.yaml: PASS
- secure_api_2.yaml: PASS

## Bug Record

Bugs found during testing: 0

No mismatch was observed between the expected vulnerability types and the detected vulnerability types for the four test datasets.

## Overall Result

All 4 datasets passed expected-vs-detected testing.

Full automated test suite: 27/27 tests passed.
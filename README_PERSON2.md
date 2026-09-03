# Person 2 - Dataset & Security Rules

## Files to add to the existing App-Security-Scanner repository

- rules/__init__.py
- rules/security_rules.py
- sample_apis/vulnerable_api.yaml
- sample_apis/secure_api.yaml
- sample_apis/labels.json
- tests/test_security_rules.py

## Implemented rules

1. Missing Authentication
2. Sensitive Data Exposure
3. Missing Input Validation
4. Missing Rate Limiting
5. Dangerous Operation Without Security

## Run tests

From the project root:

python -m unittest tests/test_security_rules.py

## Important parser integration note

The current parser only keeps the parameter type. For accurate input-validation detection, update extract_parameters() to preserve:

minLength, maxLength, minimum, maximum, pattern, enum

The current parser also does not extract x-rate-limit. Add it to normalize_endpoint() if Person 3 will scan rate limits:

"rate_limit": operation.get("x-rate-limit")

This package does not overwrite Person 1's parser. Coordinate these two small additions with Person 1.

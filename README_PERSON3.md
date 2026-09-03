# Person 3 - Scanner

The scanner connects Person 1's normalized OpenAPI parser output to Person 2's
security-rule runner. It visits every endpoint and enriches rule detections with
an ID, OWASP category, severity, confidence score, and evidence for Person 4's
reporting layer.

## Files added

- `scanner/scanner.py` - orchestration and command-line entry point
- `scanner/finding.py` - finding enrichment and OWASP/confidence metadata
- `scanner/severity.py` - severity normalization and ranking
- `scanner/__init__.py` - package interface
- `tests/test_scanner.py` - scanner integration tests

No parser, rule, dataset, or existing test file is changed by this contribution.

## Run the scanner

From the project root:

```bash
python -m scanner.scanner datasets/vulnerable/vulnerable_api_1.yaml
```

The command writes a JSON-compatible result to standard output. Person 4 can
also import `scan_file` and pass its returned dictionary directly to a reporter:

```python
from scanner.scanner import scan_file

scan_result = scan_file("datasets/vulnerable/vulnerable_api_1.yaml")
```

## Run the tests

```bash
python -m unittest tests/test_scanner.py -v
```

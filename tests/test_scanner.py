"""Tests for Person 3's scanner orchestration layer."""

from pathlib import Path
import unittest

from scanner.scanner import scan_file, scan_parsed_api


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASETS = PROJECT_ROOT / "datasets"


class TestScanner(unittest.TestCase):
    def test_scanner_detects_and_enriches_vulnerabilities(self):
        result = scan_file(DATASETS / "vulnerable" / "vulnerable_api_1.yaml")

        self.assertGreater(result["summary"]["endpoints_scanned"], 0)
        self.assertEqual(result["summary"]["total_findings"], len(result["findings"]))
        self.assertEqual(result["summary"]["highest_severity"], "HIGH")

        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("Missing Authentication", rules)
        self.assertIn("Missing Authorization", rules)

        for finding in result["findings"]:
            self.assertTrue(finding["finding_id"].startswith("F-"))
            self.assertTrue(finding["endpoint"].startswith("/"))
            self.assertTrue(finding["method"])
            self.assertNotEqual(finding["owasp_category"], "Unmapped")
            self.assertIn(finding["severity"], {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
            self.assertGreaterEqual(finding["confidence"], 0.0)
            self.assertLessEqual(finding["confidence"], 1.0)
            self.assertTrue(finding["evidence"])

    def test_secure_contract_has_no_findings(self):
        result = scan_file(DATASETS / "secure" / "secure_api_1.yaml")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["total_findings"], 0)
        self.assertEqual(result["summary"]["highest_severity"], "NONE")

    def test_scanner_visits_every_endpoint(self):
        parsed = {
            "api_info": {"title": "Test API"},
            "endpoints": [
                {"path": "/health", "method": "GET", "security": [], "parameters": [], "responses": []},
                {"path": "/users", "method": "GET", "security": [], "parameters": [], "responses": []},
            ],
        }
        result = scan_parsed_api(parsed)
        self.assertEqual(result["summary"]["endpoints_scanned"], 2)
        self.assertEqual({item["endpoint"] for item in result["findings"]}, {"/users"})

    def test_missing_file_is_reported(self):
        with self.assertRaises(FileNotFoundError):
            scan_file(DATASETS / "does_not_exist.yaml")


if __name__ == "__main__":
    unittest.main()

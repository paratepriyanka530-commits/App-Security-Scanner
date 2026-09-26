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
        self.assertEqual(
            result["summary"]["total_findings"],
            len(result["findings"]),
        )
        self.assertEqual(result["summary"]["highest_severity"], "HIGH")

        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("Missing Authentication", rules)
        self.assertIn("Missing Authorization", rules)

        for finding in result["findings"]:
            self.assertTrue(finding["finding_id"].startswith("F-"))
            self.assertTrue(finding["endpoint"].startswith("/"))
            self.assertTrue(finding["method"])
            self.assertNotEqual(finding["owasp_category"], "Unmapped")
            self.assertIn(
                finding["severity"],
                {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
            )
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
                {
                    "path": "/health",
                    "method": "GET",
                    "security": [],
                    "parameters": [],
                    "responses": [],
                },
                {
                    "path": "/users",
                    "method": "GET",
                    "security": [],
                    "parameters": [],
                    "responses": [],
                },
            ],
        }

        result = scan_parsed_api(parsed)

        self.assertEqual(result["summary"]["endpoints_scanned"], 2)

        endpoint_findings = [
            item
            for item in result["findings"]
            if item["endpoint"] is not None
        ]

        self.assertEqual(
            {item["endpoint"] for item in endpoint_findings},
            {"/users"},
        )

    def test_missing_file_is_reported(self):
        with self.assertRaises(FileNotFoundError):
            scan_file(DATASETS / "does_not_exist.yaml")

    def test_api_level_finding_has_no_fake_endpoint(self):
        parsed = {
            "api_info": {
                "title": None,
                "version": "1.0.0",
                "openapi_version": "3.0.0",
            },
            "endpoints": [
                {
                    "path": "/health",
                    "method": "GET",
                    "security": [],
                    "parameters": [],
                    "responses": [],
                }
            ],
        }

        result = scan_parsed_api(parsed)

        inventory_findings = [
            finding
            for finding in result["findings"]
            if finding["rule"] == "Incomplete API Inventory"
        ]

        self.assertEqual(len(inventory_findings), 1)
        self.assertIsNone(inventory_findings[0]["endpoint"])
        self.assertIsNone(inventory_findings[0]["method"])
        self.assertEqual(
            inventory_findings[0]["owasp_category"],
            "API9:2023 Improper Inventory Management",
        )

    def test_api10_finding_is_integrated(self):
        parsed = {
            "api_info": {
                "title": "External API Test",
                "version": "1.0.0",
                "openapi_version": "3.0.0",
            },
            "endpoints": [
                {
                    "path": "/proxy",
                    "method": "POST",
                    "security": [{"bearerAuth": []}],
                    "parameters": [],
                    "request_body": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "target_url": {
                                            "type": "string",
                                            "format": "uri",
                                        }
                                    },
                                }
                            }
                        }
                    },
                    "responses": [],
                }
            ],
        }

        result = scan_parsed_api(parsed)

        api10_findings = [
            finding
            for finding in result["findings"]
            if finding["rule"] == "Potential Unsafe API Consumption"
        ]

        self.assertEqual(len(api10_findings), 1)

        finding = api10_findings[0]

        self.assertEqual(
            finding["owasp_category"],
            "API10:2023 Unsafe Consumption of APIs",
        )
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertIsNone(finding["endpoint"])
        self.assertIsNone(finding["method"])
        self.assertGreaterEqual(finding["confidence"], 0.0)
        self.assertLessEqual(finding["confidence"], 1.0)
        self.assertTrue(finding["evidence"])


if __name__ == "__main__":
    unittest.main()
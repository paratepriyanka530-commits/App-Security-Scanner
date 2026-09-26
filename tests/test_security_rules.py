import unittest

from rules.api_inventory_rules import check_api_inventory
from rules.api_consumption_rules import check_api_consumption
from rules.resource_rules import check_resource_consumption
from rules.ssrf_rules import check_ssrf
from rules.security_rules import (
    check_missing_authentication,
    check_sensitive_data_exposure,
    check_input_validation,
    check_rate_limiting,
    check_dangerous_method_security,
    run_all_rules,
)


class TestSecurityRules(unittest.TestCase):

    def test_unsafe_api_consumption_url_input(self):
        parsed_api = {
            "endpoints": [
                {
                    "path": "/import",
                    "method": "POST",
                    "request_body": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "source_url": {
                                            "type": "string",
                                            "format": "uri",
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            ]
        }

        findings = check_api_consumption(parsed_api)

        assert any(
            finding["rule"] == "Potential Unsafe API Consumption"
            for finding in findings
        )

    def test_safe_api_consumption_without_url_input(self):
        parsed_api = {
            "endpoints": [
                {
                    "path": "/users",
                    "method": "POST",
                    "request_body": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {
                                            "type": "string",
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            ]
        }

        assert check_api_consumption(parsed_api) == []

    def test_missing_authentication(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "security": [],
            "parameters": [],
            "responses": [],
        }

        self.assertEqual(
            len(check_missing_authentication(endpoint)),
            1,
        )

    def test_sensitive_data_exposure(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "security": [],
            "parameters": [],
            "responses": [
                {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                }
                            }
                        }
                    }
                }
            ],
        }

        self.assertEqual(
            len(check_sensitive_data_exposure(endpoint)),
            1,
        )

    def test_missing_input_validation(self):
        endpoint = {
            "path": "/search",
            "method": "GET",
            "security": [],
            "parameters": [
                {
                    "name": "query",
                    "location": "query",
                    "required": False,
                    "type": "string",
                }
            ],
            "responses": [],
        }

        self.assertEqual(
            len(check_input_validation(endpoint)),
            1,
        )

    def test_rate_limiting(self):
        endpoint = {
            "path": "/login",
            "method": "POST",
            "security": [],
            "parameters": [],
            "responses": [],
        }

        self.assertEqual(
            len(check_rate_limiting(endpoint)),
            1,
        )

    def test_dangerous_method_security(self):
        endpoint = {
            "path": "/users/{id}",
            "method": "DELETE",
            "security": [],
            "parameters": [],
            "responses": [],
        }

        self.assertEqual(
            len(check_dangerous_method_security(endpoint)),
            1,
        )

    def test_secure_endpoint(self):
        endpoint = {
            "path": "/users/{id}",
            "method": "DELETE",
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "id",
                    "location": "path",
                    "required": True,
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100000,
                }
            ],
            "responses": [],
        }

        self.assertEqual(
            run_all_rules(endpoint),
            [],
        )

    def test_unbounded_pagination(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "parameters": [
                {
                    "name": "limit",
                    "location": "query",
                    "required": False,
                    "type": "integer",
                }
            ],
        }

        findings = check_resource_consumption(endpoint)

        assert any(
            finding["rule"] == "Unbounded Pagination"
            for finding in findings
        )

    def test_bounded_pagination_is_safe(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "parameters": [
                {
                    "name": "limit",
                    "location": "query",
                    "required": False,
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                }
            ],
        }

        assert check_resource_consumption(endpoint) == []

    def test_unbounded_numeric_input(self):
        endpoint = {
            "path": "/search",
            "method": "GET",
            "parameters": [
                {
                    "name": "amount",
                    "location": "query",
                    "required": False,
                    "type": "number",
                }
            ],
        }

        findings = check_resource_consumption(endpoint)

        assert any(
            finding["rule"] == "Unbounded Numeric Input"
            for finding in findings
        )

    def test_api_inventory_complete(self):
        parsed_api = {
            "api_info": {
                "title": "Test API",
                "version": "1.0.0",
                "openapi_version": "3.0.0",
            },
            "endpoints": [
                {
                    "path": "/users",
                    "method": "GET",
                }
            ],
        }

        assert check_api_inventory(parsed_api) == []

    def test_api_inventory_missing_metadata(self):
        parsed_api = {
            "api_info": {
                "title": None,
                "version": None,
                "openapi_version": None,
            },
            "endpoints": [
                {
                    "path": "/users",
                    "method": "GET",
                }
            ],
        }

        findings = check_api_inventory(parsed_api)

        assert len(findings) == 3
        assert all(
            finding["rule"] == "Incomplete API Inventory"
            for finding in findings
        )

    def test_api_inventory_empty_endpoints(self):
        parsed_api = {
            "api_info": {
                "title": "Empty API",
                "version": "1.0.0",
                "openapi_version": "3.0.0",
            },
            "endpoints": [],
        }

        findings = check_api_inventory(parsed_api)

        assert any(
            finding["rule"] == "Empty API Inventory"
            for finding in findings
        )

    def test_ssrf_url_parameter(self):
        endpoint = {
            "path": "/fetch",
            "method": "POST",
            "parameters": [
                {
                    "name": "url",
                    "location": "query",
                    "required": True,
                    "type": "string",
                    "format": "uri",
                }
            ],
        }

        findings = check_ssrf(endpoint)

        assert any(
            finding["rule"] == "Potential SSRF Input"
            for finding in findings
        )

    def test_non_url_parameter_has_no_ssrf_finding(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "parameters": [
                {
                    "name": "username",
                    "location": "query",
                    "required": True,
                    "type": "string",
                }
            ],
        }

        assert check_ssrf(endpoint) == []


if __name__ == "__main__":
    unittest.main()
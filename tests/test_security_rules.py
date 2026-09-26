import unittest
from rules.resource_rules import check_resource_consumption
from rules.ssrf_rules import check_ssrf
from rules.security_rules import (
    check_missing_authentication,
    check_sensitive_data_exposure,
    check_input_validation,
    check_rate_limiting,
    check_dangerous_method_security,
    run_all_rules
)


class TestSecurityRules(unittest.TestCase):

    def test_missing_authentication(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "security": [],
            "parameters": [],
            "responses": []
        }
        self.assertEqual(len(check_missing_authentication(endpoint)), 1)

    def test_sensitive_data_exposure(self):
        endpoint = {
            "path": "/users",
            "method": "GET",
            "security": [],
            "parameters": [],
            "responses": [{
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {
                                "username": {"type": "string"},
                                "password": {"type": "string"}
                            }
                        }
                    }
                }
            }]
        }
        self.assertEqual(len(check_sensitive_data_exposure(endpoint)), 1)

    def test_missing_input_validation(self):
        endpoint = {
            "path": "/search",
            "method": "GET",
            "security": [],
            "parameters": [{
                "name": "query",
                "location": "query",
                "required": False,
                "type": "string"
            }],
            "responses": []
        }
        self.assertEqual(len(check_input_validation(endpoint)), 1)

    def test_rate_limiting(self):
        endpoint = {
            "path": "/login",
            "method": "POST",
            "security": [],
            "parameters": [],
            "responses": []
        }
        self.assertEqual(len(check_rate_limiting(endpoint)), 1)

    def test_dangerous_method_security(self):
        endpoint = {
            "path": "/users/{id}",
            "method": "DELETE",
            "security": [],
            "parameters": [],
            "responses": []
        }
        self.assertEqual(len(check_dangerous_method_security(endpoint)), 1)

    def test_secure_endpoint(self):
        endpoint = {
            "path": "/users/{id}",
            "method": "DELETE",
            "security": [{"BearerAuth": []}],
            "parameters": [{
                "name": "id",
                "location": "path",
                "required": True,
                "type": "integer",
                "minimum": 1,
                "maximum": 100000
            }],
            "responses": []
        }
        self.assertEqual(run_all_rules(endpoint), [])

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
            ]
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
            ]
        }

        findings = check_resource_consumption(endpoint)

        assert any(
            finding["rule"] == "Unbounded Numeric Input"
            for finding in findings
        )    


if __name__ == "__main__":
    unittest.main()

import unittest
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


if __name__ == "__main__":
    unittest.main()

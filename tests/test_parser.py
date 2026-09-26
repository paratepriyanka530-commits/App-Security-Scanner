import json
import os
import sys

import pytest

# Add project root to Python path
sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
        )
    ),
)

from parser.openapi_parser import (
    load_spec,
    validate_spec,
    extract_api_info,
    extract_endpoints,
    extract_parameters,
    extract_request_body,
    extract_responses,
    extract_security_schemes,
    extract_security,
    parse_openapi,
)


def test_load_json():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    assert isinstance(spec, dict)
    assert spec["openapi"] == "3.0.0"


def test_load_yaml():
    spec = load_spec(
        "sample_apis/sample_api.yaml"
    )

    assert isinstance(spec, dict)


def test_validate_spec():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    assert validate_spec(spec) is True


def test_api_info():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    info = extract_api_info(spec)

    assert info["title"] == "Student API"
    assert info["version"] == "1.0.0"
    assert info["openapi_version"] == "3.0.0"


def test_endpoints():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    endpoints = extract_endpoints(spec)

    assert len(endpoints) == 5


def test_parameters():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    endpoints = extract_endpoints(spec)

    get_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users/{userId}"
        and endpoint["method"] == "GET"
    )

    parameters = extract_parameters(
        get_user["operation"]
    )

    assert len(parameters) == 1
    assert parameters[0]["name"] == "userId"
    assert parameters[0]["location"] == "path"
    assert parameters[0]["required"] is True


def test_request_body():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    endpoints = extract_endpoints(spec)

    post_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users"
        and endpoint["method"] == "POST"
    )

    request_body = extract_request_body(
        post_user["operation"],
        spec,
    )

    assert request_body is not None
    assert request_body["required"] is True


def test_responses():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    endpoints = extract_endpoints(spec)

    post_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users"
        and endpoint["method"] == "POST"
    )

    responses = extract_responses(
        post_user["operation"]
    )

    assert len(responses) == 2
    assert responses[0]["status_code"] == "201"


def test_security_schemes():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    schemes = extract_security_schemes(spec)

    assert "bearerAuth" in schemes
    assert schemes["bearerAuth"]["type"] == "http"


def test_endpoint_security():
    spec = load_spec(
        "sample_apis/sample_api.json"
    )

    endpoints = extract_endpoints(spec)

    get_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users/{userId}"
        and endpoint["method"] == "GET"
    )

    security = extract_security(
        get_user["operation"],
        spec,
    )

    assert security == [
        {"bearerAuth": []}
    ]


def test_full_parser():
    result = parse_openapi(
        "sample_apis/sample_api.json"
    )

    assert "api_info" in result
    assert "security_schemes" in result
    assert "endpoints" in result
    assert len(result["endpoints"]) == 5


def test_ref_resolution():
    result = parse_openapi(
        "sample_apis/ref_api.json"
    )

    schema = (
        result["endpoints"][0]
        ["request_body"]
        ["content"]["application/json"]
        ["schema"]
    )

    assert schema["type"] == "object"
    assert "name" in schema["properties"]
    assert "email" in schema["properties"]


def test_path_level_parameters():
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Path Parameter API",
            "version": "1.0.0",
        },
        "paths": {
            "/users/{userId}": {
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    }
                ],
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK",
                        }
                    }
                },
            }
        },
    }

    endpoints = extract_endpoints(spec)

    endpoint = endpoints[0]

    parameters = extract_parameters(
        endpoint["operation"],
        spec,
        endpoint["path_parameters"],
    )

    assert len(parameters) == 1
    assert parameters[0]["name"] == "userId"
    assert parameters[0]["location"] == "path"
    assert parameters[0]["required"] is True


def test_operation_parameter_overrides_path_parameter():
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Override API",
            "version": "1.0.0",
        },
        "paths": {
            "/users/{userId}": {
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    }
                ],
                "get": {
                    "parameters": [
                        {
                            "name": "userId",
                            "in": "path",
                            "required": True,
                            "schema": {
                                "type": "integer",
                            },
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "OK",
                        }
                    },
                },
            }
        },
    }

    result = parse_openapi_from_dict(spec)

    parameters = result["endpoints"][0]["parameters"]

    assert len(parameters) == 1
    assert parameters[0]["type"] == "integer"


def test_request_body_ref_resolution():
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Request Body Ref API",
            "version": "1.0.0",
        },
        "components": {
            "requestBodies": {
                "CreateUser": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {
                                        "type": "string"
                                    }
                                },
                            }
                        }
                    },
                }
            }
        },
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "$ref": "#/components/requestBodies/CreateUser"
                    },
                    "responses": {
                        "201": {
                            "description": "Created"
                        }
                    },
                }
            }
        },
    }

    operation = spec["paths"]["/users"]["post"]

    request_body = extract_request_body(
        operation,
        spec,
    )

    assert request_body is not None
    assert request_body["required"] is True

    schema = request_body["content"][
        "application/json"
    ]["schema"]

    assert schema["type"] == "object"
    assert "name" in schema["properties"]


def test_response_ref_resolution():
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Response Ref API",
            "version": "1.0.0",
        },
        "components": {
            "responses": {
                "UserResponse": {
                    "description": "User response",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "id": {
                                        "type": "integer"
                                    }
                                },
                            }
                        }
                    },
                }
            }
        },
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "$ref": "#/components/responses/UserResponse"
                        }
                    }
                }
            }
        },
    }

    operation = spec["paths"]["/users"]["get"]

    responses = extract_responses(
        operation,
        spec,
    )

    assert len(responses) == 1
    assert responses[0]["status_code"] == "200"
    assert responses[0]["description"] == "User response"

    schema = responses[0]["content"][
        "application/json"
    ]["schema"]

    assert schema["type"] == "object"
    assert "id" in schema["properties"]


def test_openapi_31_validation():
    spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "OpenAPI 3.1 API",
            "version": "1.0.0",
        },
        "paths": {
            "/health": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK"
                        }
                    }
                }
            }
        },
    }

    assert validate_spec(spec) is True


def test_load_unsupported_extension(tmp_path):
    file_path = tmp_path / "api.txt"

    file_path.write_text(
        "not an OpenAPI document",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_spec(file_path)


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_spec(
            "sample_apis/does_not_exist.yaml"
        )


def parse_openapi_from_dict(spec):
    """
    Helper used by tests for parser normalization
    without creating a temporary file.
    """
    from parser.openapi_parser import (
        validate_spec,
        extract_api_info,
        extract_security_schemes,
    )

    assert validate_spec(spec) is True

    endpoints = []

    for path, path_data in spec.get(
        "paths",
        {},
    ).items():

        path_parameters = path_data.get(
            "parameters",
            [],
        )

        for method, operation in path_data.items():

            if method.lower() in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "trace",
            }:

                from parser.openapi_parser import (
                    normalize_endpoint,
                )

                endpoints.append(
                    normalize_endpoint(
                        path,
                        method,
                        operation,
                        spec,
                        path_parameters,
                    )
                )

    return {
        "api_info": extract_api_info(spec),
        "security_schemes": extract_security_schemes(
            spec
        ),
        "endpoints": endpoints,
    }
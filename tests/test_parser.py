import sys
import os

# Add project root to Python path
sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
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
    parse_openapi
)


def test_load_json():
    spec = load_spec("sample_apis/sample_api.json")
    assert isinstance(spec, dict)
    assert spec["openapi"] == "3.0.0"


def test_load_yaml():
    spec = load_spec("sample_apis/sample_api.yaml")
    assert isinstance(spec, dict)


def test_validate_spec():
    spec = load_spec("sample_apis/sample_api.json")
    assert validate_spec(spec) is True


def test_api_info():
    spec = load_spec("sample_apis/sample_api.json")
    info = extract_api_info(spec)

    assert info["title"] == "Student API"
    assert info["version"] == "1.0.0"
    assert info["openapi_version"] == "3.0.0"


def test_endpoints():
    spec = load_spec("sample_apis/sample_api.json")
    endpoints = extract_endpoints(spec)

    assert len(endpoints) == 5


def test_parameters():
    spec = load_spec("sample_apis/sample_api.json")
    endpoints = extract_endpoints(spec)

    get_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users/{userId}"
        and endpoint["method"] == "GET"
    )

    parameters = extract_parameters(get_user["operation"])

    assert len(parameters) == 1
    assert parameters[0]["name"] == "userId"
    assert parameters[0]["location"] == "path"
    assert parameters[0]["required"] is True


def test_request_body():
    spec = load_spec("sample_apis/sample_api.json")
    endpoints = extract_endpoints(spec)

    post_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users"
        and endpoint["method"] == "POST"
    )

    request_body = extract_request_body(
        post_user["operation"],
        spec
    )

    assert request_body is not None
    assert request_body["required"] is True


def test_responses():
    spec = load_spec("sample_apis/sample_api.json")
    endpoints = extract_endpoints(spec)

    post_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users"
        and endpoint["method"] == "POST"
    )

    responses = extract_responses(post_user["operation"])

    assert len(responses) == 2
    assert responses[0]["status_code"] == "201"


def test_security_schemes():
    spec = load_spec("sample_apis/sample_api.json")
    schemes = extract_security_schemes(spec)

    assert "bearerAuth" in schemes
    assert schemes["bearerAuth"]["type"] == "http"


def test_endpoint_security():
    spec = load_spec("sample_apis/sample_api.json")
    endpoints = extract_endpoints(spec)

    get_user = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == "/users/{userId}"
        and endpoint["method"] == "GET"
    )

    security = extract_security(
        get_user["operation"],
        spec
    )

    assert security == [{"bearerAuth": []}]


def test_full_parser():
    result = parse_openapi("sample_apis/sample_api.json")

    assert "api_info" in result
    assert "security_schemes" in result
    assert "endpoints" in result
    assert len(result["endpoints"]) == 5


def test_ref_resolution():
    result = parse_openapi("sample_apis/ref_api.json")

    schema = (
        result["endpoints"][0]
        ["request_body"]
        ["content"]["application/json"]
        ["schema"]
    )

    assert schema["type"] == "object"
    assert "name" in schema["properties"]
    assert "email" in schema["properties"]
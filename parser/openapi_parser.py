import json
from pathlib import Path

import yaml

try:
    from openapi_spec_validator import validate as _validate_with_library
except ImportError:
    _validate_with_library = None


HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace",
}

VALIDATION_SCHEMA_KEYS = (
    "minLength",
    "maxLength",
    "pattern",
    "enum",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "format",
)


def _basic_validate_spec(spec):
    """Validate the OpenAPI fields the parser relies on without extras."""
    if not isinstance(spec, dict):
        raise ValueError("The OpenAPI document must be an object")

    openapi_version = spec.get("openapi")

    if not isinstance(openapi_version, str) or not openapi_version.startswith("3."):
        raise ValueError("An OpenAPI 3.x version is required")

    info = spec.get("info")

    if (
        not isinstance(info, dict)
        or not info.get("title")
        or not info.get("version")
    ):
        raise ValueError(
            "The info.title and info.version fields are required"
        )

    paths = spec.get("paths")

    if not isinstance(paths, dict):
        raise ValueError("The paths field must be an object")

    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Each path must start with '/'")

        if not isinstance(path_item, dict):
            raise ValueError(
                f"Path item for {path!r} must be an object"
            )

        for method, operation in path_item.items():

            if method.lower() in HTTP_METHODS:

                if not isinstance(operation, dict):
                    raise ValueError(
                        f"Operation {method.upper()} {path} "
                        "must be an object"
                    )

                if (
                    not isinstance(
                        operation.get("responses"),
                        dict
                    )
                    or not operation["responses"]
                ):
                    raise ValueError(
                        f"Operation {method.upper()} {path} "
                        "must define responses"
                    )


def validate_spec(spec):
    """Validate an OpenAPI specification."""
    try:
        if _validate_with_library is not None:
            _validate_with_library(spec)
        else:
            _basic_validate_spec(spec)

        return True

    except Exception as e:
        print("Invalid OpenAPI specification:")
        print(e)
        return False


def load_spec(file_path):
    """Load an OpenAPI specification from YAML or JSON."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"OpenAPI file not found: {file_path}"
        )

    suffix = path.suffix.lower()

    with path.open("r", encoding="utf-8") as file:

        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(file)

        if suffix == ".json":
            return json.load(file)

    raise ValueError(
        "Only YAML and JSON files are supported"
    )


def extract_api_info(spec):
    info = spec.get("info", {})

    return {
        "title": info.get("title"),
        "description": info.get("description"),
        "version": info.get("version"),
        "openapi_version": spec.get("openapi"),
    }


def extract_endpoints(spec):
    """Extract all HTTP operation endpoints."""
    endpoints = []

    paths = spec.get("paths", {})

    for path, path_data in paths.items():

        if not isinstance(path_data, dict):
            continue

        for method, operation in path_data.items():

            if method.lower() in HTTP_METHODS:

                endpoints.append(
                    {
                        "path": path,
                        "method": method.upper(),
                        "operation": operation,
                        "path_parameters": path_data.get(
                            "parameters",
                            [],
                        ),
                    }
                )

    return endpoints


def resolve_ref(spec, ref):
    """
    Resolve local OpenAPI references such as:

    #/components/schemas/User
    """
    if not isinstance(ref, str):
        return None

    if not ref.startswith("#/"):
        return None

    parts = ref[2:].split("/")

    current = spec

    for part in parts:

        # JSON Pointer decoding
        part = part.replace("~1", "/")
        part = part.replace("~0", "~")

        if not isinstance(current, dict):
            return None

        current = current.get(part)

        if current is None:
            return None

    return current


def resolve_refs(spec, value):
    """
    Recursively resolve local $ref values.
    """
    if isinstance(value, dict):

        if "$ref" in value:

            resolved = resolve_ref(
                spec,
                value["$ref"],
            )

            if resolved is None:
                return value

            return resolve_refs(
                spec,
                resolved,
            )

        return {
            key: resolve_refs(spec, val)
            for key, val in value.items()
        }

    if isinstance(value, list):

        return [
            resolve_refs(spec, item)
            for item in value
        ]

    return value


def _normalize_parameter(param, spec=None):
    """Normalize one OpenAPI parameter."""
    if spec is not None:
        param = resolve_refs(spec, param)

    if not isinstance(param, dict):
        return None

    schema = param.get("schema", {})

    if spec is not None:
        schema = resolve_refs(spec, schema)

    if not isinstance(schema, dict):
        schema = {}

    parameter = {
        "name": param.get("name"),
        "location": param.get("in"),
        "required": param.get("required", False),
        "type": schema.get("type"),
    }

    parameter.update(
        {
            key: schema[key]
            for key in VALIDATION_SCHEMA_KEYS
            if key in schema
        }
    )

    return parameter


def extract_parameters(
    operation,
    spec=None,
    path_parameters=None,
):
    """
    Extract operation-level and path-level parameters.

    If the same parameter exists at both levels,
    the operation-level parameter overrides the
    path-level parameter.
    """
    parameters = {}

    path_parameters = path_parameters or []

    # Path-level parameters first.
    for param in path_parameters:

        normalized = _normalize_parameter(
            param,
            spec,
        )

        if normalized is None:
            continue

        key = (
            normalized.get("name"),
            normalized.get("location"),
        )

        parameters[key] = normalized

    # Operation-level parameters override path-level ones.
    for param in operation.get("parameters", []):

        normalized = _normalize_parameter(
            param,
            spec,
        )

        if normalized is None:
            continue

        key = (
            normalized.get("name"),
            normalized.get("location"),
        )

        parameters[key] = normalized

    return list(parameters.values())


def extract_request_body(operation, spec):
    """Extract and resolve an operation request body."""
    request_body = operation.get("requestBody")

    if not request_body:
        return None

    request_body = resolve_refs(
        spec,
        request_body,
    )

    if not isinstance(request_body, dict):
        return None

    return {
        "required": request_body.get(
            "required",
            False,
        ),
        "content": resolve_refs(
            spec,
            request_body.get(
                "content",
                {},
            ),
        ),
    }


def extract_responses(operation, spec=None):
    """Extract and resolve operation responses."""
    responses = []

    for status_code, response in operation.get(
        "responses",
        {},
    ).items():

        if spec is not None:
            response = resolve_refs(
                spec,
                response,
            )

        if not isinstance(response, dict):
            response = {}

        responses.append(
            {
                "status_code": status_code,
                "description": response.get(
                    "description"
                ),
                "content": resolve_refs(
                    spec,
                    response.get(
                        "content",
                        {},
                    ),
                )
                if spec is not None
                else response.get(
                    "content",
                    {},
                ),
                "headers": resolve_refs(
                    spec,
                    response.get(
                        "headers",
                        {},
                    ),
                )
                if spec is not None
                else response.get(
                    "headers",
                    {},
                ),
            }
        )

    return responses


def extract_security_schemes(spec):
    components = spec.get(
        "components",
        {},
    )

    schemes = components.get(
        "securitySchemes",
        {},
    )

    return resolve_refs(
        spec,
        schemes,
    )


def extract_security(operation, spec):
    """
    Operation-level security overrides global security.

    security: [] intentionally means anonymous access.
    """
    if "security" in operation:
        return operation["security"]

    return spec.get(
        "security",
        [],
    )


def normalize_endpoint(
    path,
    method,
    operation,
    spec,
    path_parameters=None,
):
    return {
        "path": path,
        "method": method.upper(),

        "summary": operation.get(
            "summary"
        ),

        "description": operation.get(
            "description"
        ),

        "parameters": extract_parameters(
            operation,
            spec,
            path_parameters,
        ),

        "request_body": extract_request_body(
            operation,
            spec,
        ),

        "responses": extract_responses(
            operation,
            spec,
        ),

        "security": extract_security(
            operation,
            spec,
        ),

        "rate_limit": operation.get(
            "x-rate-limit"
        ),

        "required_security_headers": operation.get(
            "x-required-security-headers",
            [],
        ),

        "required_roles": operation.get(
            "x-required-roles"
        ),
    }


def parse_openapi(file_path):
    """Load, validate, and normalize an OpenAPI specification."""

    # Step 1: Load
    spec = load_spec(file_path)

    # Step 2: Validate
    if not validate_spec(spec):
        raise ValueError(
            "Invalid OpenAPI specification"
        )

    # Step 3: API information
    api_info = extract_api_info(spec)

    # Step 4: Security schemes
    security_schemes = extract_security_schemes(
        spec
    )

    # Step 5: Extract and normalize endpoints
    endpoints = []

    paths = spec.get(
        "paths",
        {},
    )

    for path, path_data in paths.items():

        if not isinstance(path_data, dict):
            continue

        path_parameters = path_data.get(
            "parameters",
            [],
        )

        for method, operation in path_data.items():

            if method.lower() in HTTP_METHODS:

                endpoint = normalize_endpoint(
                    path,
                    method,
                    operation,
                    spec,
                    path_parameters,
                )

                endpoints.append(endpoint)

    return {
        "api_info": api_info,
        "security_schemes": security_schemes,
        "endpoints": endpoints,
    }


if __name__ == "__main__":
    result = parse_openapi(
        "sample_apis/sample_api.json"
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )
import yaml
import json
from openapi_spec_validator import validate


def validate_spec(spec):
    try:
        validate(spec)
        return True

    except Exception as e:
        print("Invalid OpenAPI specification:")
        print(e)
        return False


def load_spec(file_path):

    with open(file_path, "r", encoding="utf-8") as file:

        if file_path.endswith((".yaml", ".yml")):
            return yaml.safe_load(file)

        elif file_path.endswith(".json"):
            return json.load(file)

        else:
            raise ValueError(
                "Only YAML and JSON files are supported"
            )

def extract_api_info(spec):
    info = spec.get("info", {})

    return {
        "title": info.get("title"),
        "description": info.get("description"),
        "version": info.get("version"),
        "openapi_version": spec.get("openapi")
    }  

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "trace"
}


def extract_endpoints(spec):
    endpoints = []

    paths = spec.get("paths", {})

    for path, path_data in paths.items():

        for method, operation in path_data.items():

            if method.lower() in HTTP_METHODS:

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "operation": operation
                })

    return endpoints      

def extract_parameters(operation):

    parameters = []

    for param in operation.get("parameters", []):

        schema = param.get("schema", {})

        parameters.append({
            "name": param.get("name"),
            "location": param.get("in"),
            "required": param.get("required", False),
            "type": schema.get("type")
        })

    return parameters

def extract_request_body(operation, spec):

    request_body = operation.get("requestBody")

    if not request_body:
        return None

    return {
        "required": request_body.get("required", False),
        "content": resolve_refs(
            spec,
            request_body.get("content", {})
            )
        }

def extract_responses(operation):

    responses = []

    for status_code, response in operation.get("responses", {}).items():

        responses.append({
            "status_code": status_code,
            "description": response.get("description"),
            "content": response.get("content", {})
        })

    return responses
def extract_security_schemes(spec):

    components = spec.get("components", {})

    return components.get("securitySchemes", {})

def extract_security(operation, spec):
    if "security" in operation:
        return operation["security"]

    return spec.get("security", []) 

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
                value["$ref"]
            )

            if resolved is None:
                return value

            return resolve_refs(
                spec,
                resolved
            )

        return {
            key: resolve_refs(spec, val)
            for key, val in value.items()
        }

    elif isinstance(value, list):

        return [
            resolve_refs(spec, item)
            for item in value
        ]

    return value

def normalize_endpoint(path, method, operation, spec):

    return {
        "path": path,
        "method": method.upper(),

        "summary": operation.get("summary"),
        "description": operation.get("description"),

        "parameters": extract_parameters(
            operation
        ),

        "request_body": extract_request_body(
            operation,
            spec
        ),

        "responses": extract_responses(
            operation
        ),

        "security": extract_security(
            operation,
            spec
        )
    }

def parse_openapi(file_path):

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

    paths = spec.get("paths", {})

    for path, path_data in paths.items():

        for method, operation in path_data.items():

            if method.lower() in HTTP_METHODS:

                endpoint = normalize_endpoint(
                    path,
                    method,
                    operation,
                    spec
                )

                endpoints.append(endpoint)

    # Final normalized result
    return {
        "api_info": api_info,
        "security_schemes": security_schemes,
        "endpoints": endpoints
    }

if __name__ == "__main__":
    result = parse_openapi("sample_apis/sample_api.json")
    import json
    print(json.dumps(result, indent=2))
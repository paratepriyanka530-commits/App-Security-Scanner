import yaml
import json


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


if __name__ == "__main__":

    data = load_spec(
        "sample_apis/sample_api.yaml"
    )

    print(data)
    
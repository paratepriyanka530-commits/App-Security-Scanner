"""Ollama implementation of the model-agnostic LLM provider interface."""

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ai_analysis.llm.base import LLMProvider, LLMProviderError


class OllamaConnectionError(LLMProviderError):
    """Raised when the Ollama service cannot be reached in time."""


class OllamaResponseError(LLMProviderError):
    """Raised when Ollama returns an HTTP or response-format error."""


class OllamaProvider(LLMProvider):
    """Generate text through a locally served Ollama HTTP API."""

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
    ):
        if not isinstance(model, str):
            raise TypeError("model must be a string")
        if not model.strip():
            raise ValueError("model must not be empty")
        if not isinstance(base_url, str):
            raise TypeError("base_url must be a string")

        parsed_url = urlparse(base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
        if parsed_url.query or parsed_url.fragment:
            raise ValueError("base_url must not contain a query or fragment")

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout must be a number")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.model = model.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)

    def generate(self, prompt: str) -> str:
        """Return only generated model text from Ollama's generate endpoint."""
        self.validate_prompt(prompt)

        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
            }
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                status = response.getcode()
                if status is not None and not 200 <= status < 300:
                    raise OllamaResponseError(
                        f"Ollama returned HTTP status {status}"
                    )
                response_body = response.read()
        except HTTPError as error:
            raise OllamaResponseError(
                f"Ollama returned HTTP status {error.code}"
            ) from error
        except (socket.timeout, TimeoutError) as error:
            raise OllamaConnectionError("Ollama request timed out") from error
        except URLError as error:
            if isinstance(error.reason, (socket.timeout, TimeoutError)):
                message = "Ollama request timed out"
            else:
                message = "Unable to connect to the Ollama server"
            raise OllamaConnectionError(message) from error
        except OSError as error:
            raise OllamaConnectionError(
                "Unable to connect to the Ollama server"
            ) from error

        try:
            ollama_response = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OllamaResponseError(
                "Ollama returned an invalid JSON response"
            ) from error

        if not isinstance(ollama_response, dict):
            raise OllamaResponseError("Ollama response must be a JSON object")

        generated_text = ollama_response.get("response")
        if not isinstance(generated_text, str) or not generated_text.strip():
            raise OllamaResponseError(
                "Ollama response is missing non-empty generated text"
            )

        return generated_text

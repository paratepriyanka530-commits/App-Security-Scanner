"""Deterministic LLM provider used by tests and local development."""

from ai_analysis.llm.base import LLMProvider


class MockLLMProvider(LLMProvider):
    """Return a predefined response without making a network call."""

    def __init__(self, response: str):
        if not isinstance(response, str):
            raise TypeError("response must be a string")
        self.response = response
        self.last_prompt: str | None = None

    def generate(self, prompt: str) -> str:
        self.validate_prompt(prompt)
        self.last_prompt = prompt
        return self.response

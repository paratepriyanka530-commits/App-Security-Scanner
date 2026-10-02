"""Abstract interface for text-generating LLM providers."""

from abc import ABC, abstractmethod


class LLMProviderError(RuntimeError):
    """Base exception for failures communicating with an LLM provider."""


class LLMProvider(ABC):
    """Model-agnostic interface used by the semantic analyzer."""

    @staticmethod
    def validate_prompt(prompt: str) -> None:
        """Validate the common prompt contract for provider implementations."""
        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")
        if not prompt.strip():
            raise ValueError("prompt must not be empty")

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate a text response for a non-empty prompt."""
        raise NotImplementedError

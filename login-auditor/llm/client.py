#the only file that talks to the LLM

from __future__ import annotations

import os
from typing import Protocol

DEFAULT_MODEL = "claude-sonnet-5-5"     # override with LLM_MODEL in .env


class LLMError(Exception):
    """The LLM call itself failed (network, bad key, rate limit...)."""


class LLMClient(Protocol):
    def complete(self, system: str, user: str, max_tokens: int = 1000) -> str: ...


class AnthropicClient:
    def __init__(self, model: str | None = None):
        import anthropic                      # imported here so tests don't need it
        self._client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        self.model = model or os.getenv("LLM_MODEL", DEFAULT_MODEL)

    def complete(self, system: str, user: str, max_tokens: int = 1000) -> str:
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as e:
            raise LLMError(str(e)) from e
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


def get_default_client() -> LLMClient:
    try:
        from dotenv import load_dotenv
        load_dotenv()                          # loads ANTHROPIC_API_KEY from .env
    except ImportError:
        pass
    try:
        return AnthropicClient()
    except Exception as e:
        raise LLMError(f"Could not create LLM client: {e}") from e
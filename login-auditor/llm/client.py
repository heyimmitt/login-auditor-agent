from __future__ import annotations

import os
from typing import Protocol


class LLMError(Exception):
    """The LLM call itself failed (network, bad key, rate limit...)."""


class LLMClient(Protocol):
    def complete(self, system: str, user: str, max_tokens: int = 1000) -> str: ...


class OpenAICompatibleClient:
    def __init__(self):
        from openai import OpenAI              # imported here so tests don't need it
        self.base_url = os.getenv("LLM_BASE_URL") or None   # None = real OpenAI
        self._client = OpenAI(
            api_key=os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY"),
            base_url=self.base_url,
        )
        self.model = os.environ["LLM_MODEL"]   # required: set it in .env

    def complete(self, system: str, user: str, max_tokens: int = 1000) -> str:
        # Real OpenAI uses max_completion_tokens; other providers use max_tokens.
        limit = ({"max_completion_tokens": max_tokens} if self.base_url is None
                 else {"max_tokens": max_tokens})
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                **limit,
            )
        except Exception as e:
            raise LLMError(str(e)) from e
        return resp.choices[0].message.content or ""


def get_default_client() -> LLMClient:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    try:
        return OpenAICompatibleClient()
    except Exception as e:
        raise LLMError(f"Could not create LLM client: {e}") from e
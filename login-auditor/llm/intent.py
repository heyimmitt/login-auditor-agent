#step where the agent works out what the user is asking
#code can only act on a structured query
#turns text prompt into query form

from __future__ import annotations

import json
import re
from datetime import datetime

from pydantic import ValidationError

from contracts.models import Query
from llm.client import LLMClient
from llm.prompts import INTENT_SYSTEM
from timelogic.windows import WINDOW_LABELS

MAX_ATTEMPTS = 2     # first try + one retry
_ALLOWED_CONDITIONS = {None, "outside_business_hours"}


class NeedsClarification(Exception):
    """Question unclear or off-topic. `message` is what to ask the user."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class IntentError(Exception):
    """The model never produced a valid query."""


def _extract_json(text: str) -> dict:
    """Pull the JSON object out of the reply (handles ```json fences)."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object found")
    data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("JSON is not an object")
    return data


def _to_query(data: dict) -> Query:
    """Validate the JSON against our Query model and the allowed values."""
    if data.get("condition") in ("", "none", "null"):
        data["condition"] = None
    query = Query.model_validate(data)
    if query.time_window not in WINDOW_LABELS:
        raise ValueError(f"time_window must be one of {WINDOW_LABELS}")
    if query.condition not in _ALLOWED_CONDITIONS:
        raise ValueError("condition must be 'outside_business_hours' or null")
    return query


def parse_intent(prompt: str, now: datetime, llm: LLMClient) -> Query:
    """Raises NeedsClarification or IntentError. LLMError passes through."""
    user_msg = f"Today is {now:%A %Y-%m-%d}.\n<question>\n{prompt}\n</question>"
    last_error = "unknown"
    for _ in range(MAX_ATTEMPTS):
        reply = llm.complete(INTENT_SYSTEM, user_msg, max_tokens=300)
        try:
            data = _extract_json(reply)
            if "clarification" in data:
                raise NeedsClarification(str(data["clarification"]))
            return _to_query(data)
        except NeedsClarification:
            raise
        except (ValueError, ValidationError) as e:
            last_error = str(e)           # tell the model what was wrong and retry
            user_msg += (
                f"\n\nYour previous reply was invalid ({last_error}). "
                "Reply with only the JSON object."
            )
    raise IntentError(f"Could not parse a valid query: {last_error}")
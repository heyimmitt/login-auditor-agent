#This is the step where the LLM filters timestamps

"""Ask the LLM which events fall outside business hours.
The result is only a cross-check: audit.py still trusts the code's answer."""
from __future__ import annotations

import json

from contracts.models import LoginEvent
from llm.client import LLMClient
from llm.intent import _extract_json
from llm.prompts import FILTER_SYSTEM
from llm.summarize import _clean
from timelogic.policy import Policy

MAX_EVENTS = 200   # beyond this, skip the LLM filter to keep the prompt small


class LLMFilterError(Exception):
    """The LLM's filtering reply was unusable, or there were too many events."""


def llm_filter(events: list[LoginEvent], policy: Policy, llm: LLMClient) -> set[int]:
    """Return the indexes (positions in `events`) the LLM says are outside hours."""
    if not events:
        return set()
    if len(events) > MAX_EVENTS:
        raise LLMFilterError(f"{len(events)} events is more than the limit of {MAX_EVENTS}")

    rows = [
        {
            "id": i,
            "time": e.timestamp.astimezone(policy.tz).strftime("%a %Y-%m-%d %H:%M"),
            "user": _clean(e.user),
            "event_type": e.event_type.value,
        }
        for i, e in enumerate(events)
    ]
    holidays = ", ".join(sorted(d.isoformat() for d in policy.holidays)) or "none"
    user_msg = (
        f"Policy (trusted): {policy.describe()}. Holidays: {holidays}.\n"
        "<log_data>\n"
        f"{json.dumps(rows, indent=2)}\n"
        "</log_data>"
    )

    reply = llm.complete(FILTER_SYSTEM, user_msg, max_tokens=800)
    try:
        ids = _extract_json(reply)["outside_hours"]
    except (ValueError, KeyError) as e:
        raise LLMFilterError(f"unusable reply: {e}") from e

    if not isinstance(ids, list) or not all(
        isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(events) for i in ids
    ):
        raise LLMFilterError("ids must be a list of valid event numbers")
    return set(ids)
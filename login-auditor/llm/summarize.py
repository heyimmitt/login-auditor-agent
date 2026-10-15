#never sends raw log lines to the model and cleans attacker-controlled text first.

from __future__ import annotations

import json
import re
from zoneinfo import ZoneInfo

from contracts.models import LoginEvent
from llm.client import LLMClient, LLMError
from llm.prompts import SUMMARY_SYSTEM

MAX_EVENTS = 50
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value, limit: int = 64):
    """Make log text safe: no control characters, no < or > (so it can't
    close our <log_data> tag), and cut to a short length."""
    if value is None:
        return None
    return _CONTROL.sub(" ", str(value)).replace("<", "").replace(">", "")[:limit]


def _event_for_prompt(e: LoginEvent, tz: ZoneInfo) -> dict:
    """Only parsed fields go to the model. The raw log line is never sent."""
    return {
        "time": e.timestamp.astimezone(tz).strftime("%a %Y-%m-%d %H:%M:%S"),
        "user": _clean(e.user),
        "event_type": e.event_type.value,
        "method": _clean(e.method),
        "remote_ip": _clean(e.remote_ip),
        "source": e.source,
    }


def fallback_summary(events: list[LoginEvent], scope: dict, tz: ZoneInfo) -> str:
    """Plain code-built answer: used for zero results or if the LLM fails."""
    header = f"Searched {scope.get('window')} (policy: {scope.get('policy')})."
    if not events:
        return f"No matching login events found. {header}"
    lines = [f"{len(events)} matching event(s). {header}"]
    for e in events[:MAX_EVENTS]:
        d = _event_for_prompt(e, tz)
        lines.append(
            f"- {d['time']} {d['user']} {d['event_type']} "
            f"from {d['remote_ip'] or 'n/a'} ({d['method'] or 'n/a'}, {d['source']})"
        )
    return "\n".join(lines)


def summarize(question: str, events: list[LoginEvent], scope: dict,
              llm: LLMClient, tz: ZoneInfo) -> str:
    if not events:                      # nothing to explain, so skip the LLM call
        return fallback_summary(events, scope, tz)

    shown = [_event_for_prompt(e, tz) for e in events[:MAX_EVENTS]]
    user_msg = (
        f"Question: {question}\n\n"
        f"Scope (trusted): {json.dumps(scope)}\n\n"
        f"Total matching events: {len(events)} (showing {len(shown)})\n"
        "<log_data>\n"
        f"{json.dumps(shown, indent=2)}\n"
        "</log_data>"
    )
    try:
        text = llm.complete(SUMMARY_SYSTEM, user_msg, max_tokens=800).strip()
    except LLMError:
        return fallback_summary(events, scope, tz)
    return text or fallback_summary(events, scope, tz)
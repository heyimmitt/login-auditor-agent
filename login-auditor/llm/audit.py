"""The single front door of the agent: audit(prompt, now) -> AuditResult."""
from __future__ import annotations

from datetime import datetime
from typing import Callable

from contracts.models import AuditResult, EventType, LoginEvent
from llm.client import LLMClient, LLMError, get_default_client
from llm.intent import IntentError, NeedsClarification, parse_intent
from llm.llm_filter import LLMFilterError, llm_filter
from llm.summarize import summarize
from pipeline.errors import LogReadError
from timelogic.policy import Policy, is_outside_business_hours, load_policy
from timelogic.windows import describe_window, resolve_window

RunQuery = Callable[[str | None, list[EventType], datetime, datetime], list[LoginEvent]]
SOURCES = ["last", "auth.log"]


def audit(
    prompt: str,
    now: datetime | None = None,
    *,
    filter_mode: str = "llm",             # "code" or "llm" (llm = also ask the LLM to filter)
    llm: LLMClient | None = None,          # tests pass a fake LLM here
    run_query_fn: RunQuery | None = None,  # --fixtures passes a fake pipeline here
    policy: Policy | None = None,
) -> AuditResult:
    # 1. Fix "now" once for the whole call.
    policy = policy or load_policy()
    now = now or datetime.now(policy.tz)
    if now.tzinfo is None:
        now = now.replace(tzinfo=policy.tz)
    if run_query_fn is None:
        from pipeline.query import run_query as run_query_fn   # Person A's function

    # 2. Question -> structured Query (LLM, validated).
    try:
        llm = llm or get_default_client()
        query = parse_intent(prompt, now, llm)
    except NeedsClarification as c:
        return AuditResult(status="needs_clarification", summary=c.message)
    except IntentError:
        return AuditResult(
            status="needs_clarification",
            summary="I couldn't turn that into a login query. Could you rephrase it?",
        )
    except LLMError as e:
        return AuditResult(status="error", summary="The language model is unavailable.",
                           error=str(e))

    # 3. Window label -> exact datetimes (code, not LLM).
    start, end = resolve_window(query.time_window, now, policy.tz)

    # 4. Person A's pipeline: collect, parse, filter by user/type/window.
    try:
        events = run_query_fn(query.target_user, query.event_types, start, end)
    except LogReadError as e:
        return AuditResult(status="error", summary=f"Could not read the login logs: {e}",
                           error=str(e))

    
    # 5. Business-hours filtering.
    # The LLM determines which events are outside business hours.
    code_idx = {
        i for i, e in enumerate(events)
        if is_outside_business_hours(e.timestamp, policy)
    } if query.condition == "outside_business_hours" else set(range(len(events)))

    llm_check = None

    if query.condition == "outside_business_hours":
        try:
            llm_idx = llm_filter(events, policy, llm)

            # Validate returned indexes before using them.
            if any(
                not isinstance(i, int) or isinstance(i, bool)
                or i < 0 or i >= len(events)
                for i in llm_idx
            ):
                raise LLMFilterError(
                    "The LLM returned invalid event indexes."
                )

            # IMPORTANT: the LLM result determines the final events.
            flagged = [events[i] for i in sorted(llm_idx)]

            # Python is used only to evaluate LLM accuracy.
            llm_check = {
                "status": "agreed" if llm_idx == code_idx else "disagreed",
                "code_count": len(code_idx),
                "llm_count": len(llm_idx),
                "missed_by_llm": sorted(code_idx - llm_idx),
                "extra_by_llm": sorted(llm_idx - code_idx),
            }

        except (LLMFilterError, LLMError) as e:
            return AuditResult(
                status="error",
                summary="The LLM could not filter the login events.",
                error=str(e),
            )
    else:
        flagged = events


    # 6. Explain the (small) result in plain English.
    scope = {
    "window": describe_window(start, end, policy.tz),
    "policy": policy.describe(),
    "user": query.target_user or "any user",
    "event_types": [t.value for t in query.event_types],
    "condition": query.condition or "none",
    "sources": SOURCES,
    "events_considered": len(events),
    "events_flagged": len(flagged),
}

    if llm_check is not None:
        scope["llm_filter_check"] = llm_check
        
    summary = summarize(prompt, flagged, scope, llm, policy.tz)

    return AuditResult(
        status="ok" if flagged else "no_matches",
        summary=summary,
        events=flagged,
        scope=scope,
    )
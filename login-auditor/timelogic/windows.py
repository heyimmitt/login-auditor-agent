"""Turn window labels ('this_week', 'last_night', ...) into exact datetimes.
Rules live here (and in DECISIONS.md) so the LLM never does calendar math."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

# The only labels the LLM is allowed to choose from.
WINDOW_LABELS = (
    "today", "yesterday", "last_night", "this_week",
    "last_week", "last_7_days", "last_24_hours",
)


def _at(d: date, t: time, tz: ZoneInfo) -> datetime:
    return datetime.combine(d, t, tzinfo=tz)


def resolve_window(label: str, now: datetime, tz: ZoneInfo) -> tuple[datetime, datetime]:
    """Return (start, end). Start is inclusive, end is exclusive."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(tz)
    today = now.date()
    yesterday = today - timedelta(days=1)
    monday = today - timedelta(days=today.weekday())   # Monday of this week

    if label == "today":
        return _at(today, time.min, tz), now
    if label == "yesterday":
        return _at(yesterday, time.min, tz), _at(today, time.min, tz)
    if label == "last_night":      # 18:00 yesterday to 06:00 today
        return _at(yesterday, time(18, 0), tz), min(_at(today, time(6, 0), tz), now)
    if label == "this_week":       # Monday 00:00 to now
        return _at(monday, time.min, tz), now
    if label == "last_week":
        return _at(monday - timedelta(days=7), time.min, tz), _at(monday, time.min, tz)
    if label == "last_7_days":
        return now - timedelta(days=7), now
    if label == "last_24_hours":
        return now - timedelta(hours=24), now
    raise ValueError(f"Unknown time window label: {label!r}")


def describe_window(start: datetime, end: datetime, tz: ZoneInfo) -> str:
    """Readable text for the answer, e.g. 'Mon 2026-10-05 00:00 to Sun ...'."""
    fmt = "%a %Y-%m-%d %H:%M"
    return f"{start.astimezone(tz):{fmt}} to {end.astimezone(tz):{fmt}} ({tz.key})"
"""Person A's handoff to B: collect, parse, and filter login events."""
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from contracts.models import EventType, LoginEvent
from pipeline import DEFAULT_TZ
from pipeline.collectors import file_mtime, find_auth_logs, read_lines, run_command
from pipeline.parsers.auth_log import parse_auth_log
from pipeline.parsers.last import parse_last


def run_query(
    user: str | None,
    event_types: list[EventType] | None,
    start: datetime,
    end: datetime,
    *,
    auth_log_paths: list[Path] | None = None,
    last_output: str | None = None,
    tz: ZoneInfo = DEFAULT_TZ,
) -> list[LoginEvent]:
    """All events in `start <= t < end`, sorted by time, with no deduplication.

    `user=None` means any user; a user also matches sudo/su events they ran (actor).
    `event_types=None` means all types. `auth_log_paths` and `last_output` replace the
    real sources (for tests). Raises LogReadError if a needed source can't be read.
    """
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("start and end must be timezone-aware")
    if start > end:
        raise ValueError(f"start {start} is after end {end}")
    types = set(event_types) if event_types is not None else set(EventType)

    events: list[LoginEvent] = []
    paths = auth_log_paths if auth_log_paths is not None else find_auth_logs()
    for path in paths:
        mtime = file_mtime(path, tz)
        if mtime < start:   # every line in the file is older than the window
            continue
        events += parse_auth_log(read_lines(path), reference=mtime, tz=tz)

    # `last` only ever reports successful sessions.
    if EventType.login_success in types:
        output = last_output if last_output is not None else run_command("last", tz)
        events += parse_last(output, tz)

    matched = [
        e for e in events
        if e.event_type in types
        and start <= e.timestamp < end
        and (user is None or user in (e.user, e.actor))
    ]
    return sorted(matched, key=lambda e: e.timestamp)

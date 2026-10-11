"""STUB: Person A owns and replaces this file. B only calls run_query()."""
from datetime import datetime

from contracts.models import EventType, LoginEvent


def run_query(
    user: str | None,
    event_types: list[EventType],
    start: datetime,
    end: datetime,
) -> list[LoginEvent]:
    """Collect, parse, and filter. Returns events sorted by timestamp.
    Raises LogReadError if a source can't be read."""
    raise NotImplementedError("Person A: implement run_query (use --fixtures meanwhile)")

#fake pipeline for development

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from contracts.models import EventType, LoginEvent

DEFAULT_FIXTURES = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "events.json"


def make_fixture_run_query(path: Path | str = DEFAULT_FIXTURES):
    """Behaves like A's run_query, but reads data/fixtures/events.json."""
    events = [LoginEvent.model_validate(d) for d in json.loads(Path(path).read_text("utf-8"))]

    def run_query(user: str | None, event_types: list[EventType],
                  start: datetime, end: datetime) -> list[LoginEvent]:
        hits = [
            e for e in events
            if (user is None or e.user == user)
            and e.event_type in event_types
            and start <= e.timestamp < end
        ]
        return sorted(hits, key=lambda e: e.timestamp)

    return run_query
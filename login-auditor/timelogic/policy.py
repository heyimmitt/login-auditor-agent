"""Business-hours policy: load config, decide what counts as 'outside hours'."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"
_DAY_INDEX = {"Mon": 0, "Tue": 1, "Wed": 2, "Thu": 3, "Fri": 4, "Sat": 5, "Sun": 6}


@dataclass(frozen=True)
class Policy:
    tz: ZoneInfo
    weekdays: frozenset[int]      # 0 = Monday
    start: time                   # inclusive
    end: time                     # exclusive
    holidays: frozenset[date]

    def describe(self) -> str:
        days = ", ".join(n for n, i in _DAY_INDEX.items() if i in self.weekdays)
        return f"{days} {self.start:%H:%M}-{self.end:%H:%M} {self.tz.key}"


def load_policy(path: Path | str = DEFAULT_POLICY_PATH) -> Policy:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)["business_hours"]
    return Policy(
        tz=ZoneInfo(raw["timezone"]),
        weekdays=frozenset(_DAY_INDEX[d] for d in raw["weekdays"]),
        start=time.fromisoformat(str(raw["start"])),
        end=time.fromisoformat(str(raw["end"])),
        holidays=frozenset(date.fromisoformat(str(h)) for h in (raw.get("holidays") or [])),
    )


def is_outside_business_hours(ts: datetime, policy: Policy) -> bool:
    """True if ts falls on a holiday, a non-working day, or outside [start, end)."""
    if ts.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    local = ts.astimezone(policy.tz)
    if local.date() in policy.holidays:
        return True
    if local.weekday() not in policy.weekdays:
        return True
    return not (policy.start <= local.time() < policy.end)

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from timelogic.policy import is_outside_business_hours, load_policy

IST = ZoneInfo("Asia/Kolkata")
policy = load_policy()


def at(day: int, hh: int, mm: int = 0) -> datetime:
    # Oct 5 2026 is a Monday; Oct 10 is Saturday; Oct 11 is Sunday
    return datetime(2026, 10, day, hh, mm, tzinfo=IST)


@pytest.mark.parametrize("ts,expected", [
    (at(5, 8, 59), True),     # just before opening
    (at(5, 9, 0), False),     # opening is inclusive
    (at(5, 17, 59), False),
    (at(5, 18, 0), True),     # closing is exclusive
    (at(10, 12, 0), True),    # Saturday
    (at(11, 12, 0), True),    # Sunday
])
def test_boundaries(ts, expected):
    assert is_outside_business_hours(ts, policy) is expected


def test_converts_other_timezones():
    utc = ZoneInfo("UTC")
    # 04:00 UTC = 09:30 IST on a Monday -> inside hours
    assert not is_outside_business_hours(datetime(2026, 10, 5, 4, 0, tzinfo=utc), policy)


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        is_outside_business_hours(datetime(2026, 10, 5, 10, 0), policy)

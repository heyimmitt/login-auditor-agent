from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from timelogic.windows import resolve_window

IST = ZoneInfo("Asia/Kolkata")
NOW = datetime(2026, 10, 6, 14, 32, tzinfo=IST)  # Tuesday


def d(day, hh=0, mm=0, month=10):
    return datetime(2026, month, day, hh, mm, tzinfo=IST)


@pytest.mark.parametrize("label,start,end", [
    ("this_week", d(5), NOW),
    ("today", d(6), NOW),
    ("yesterday", d(5), d(6)),
    ("last_night", d(5, 18), d(6, 6)),
    ("last_week", d(28, month=9), d(5)),
    ("last_24_hours", d(5, 14, 32), NOW),
])
def test_windows(label, start, end):
    assert resolve_window(label, NOW, IST) == (start, end)


def test_last_night_capped_at_now():
    early = datetime(2026, 10, 6, 3, 0, tzinfo=IST)
    assert resolve_window("last_night", early, IST)[1] == early


def test_unknown_label():
    with pytest.raises(ValueError):
        resolve_window("next_century", NOW, IST)

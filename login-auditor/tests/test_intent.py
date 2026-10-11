from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from llm.intent import IntentError, NeedsClarification, parse_intent
from tests.fakes import FakeLLM

NOW = datetime(2026, 10, 6, 14, 32, tzinfo=ZoneInfo("Asia/Kolkata"))
GOOD = ('{"target_user": "root", "event_types": ["login_success"], '
        '"time_window": "this_week", "condition": "outside_business_hours"}')


def test_valid_json():
    q = parse_intent("root off-hours this week", NOW, FakeLLM(GOOD))
    assert q.target_user == "root" and q.condition == "outside_business_hours"


def test_code_fenced_json():
    q = parse_intent("x", NOW, FakeLLM(f"```json\n{GOOD}\n```"))
    assert q.time_window == "this_week"


def test_retry_after_invalid_reply():
    llm = FakeLLM("sorry, here you go!", GOOD)
    q = parse_intent("x", NOW, llm)
    assert q.target_user == "root" and len(llm.calls) == 2
    assert "invalid" in llm.calls[1][1]


def test_clarification():
    llm = FakeLLM('{"clarification": "What about logins?"}')
    with pytest.raises(NeedsClarification) as e:
        parse_intent("weather?", NOW, llm)
    assert "logins" in e.value.message


def test_bad_window_label_twice_fails():
    bad = '{"target_user": null, "event_types": ["login_success"], "time_window": "forever"}'
    with pytest.raises(IntentError):
        parse_intent("x", NOW, FakeLLM(bad, bad))

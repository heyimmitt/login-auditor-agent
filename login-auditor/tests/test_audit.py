from datetime import datetime
from zoneinfo import ZoneInfo

from llm.audit import audit
from llm.dev_fixtures import make_fixture_run_query
from pipeline.errors import LogReadError
from tests.fakes import FakeLLM

IST = ZoneInfo("Asia/Kolkata")
NOW = datetime(2026, 10, 11, 10, 0, tzinfo=IST)  # Sunday
ROOT_OFFHOURS = ('{"target_user": "root", "event_types": ["login_success"], '
                 '"time_window": "this_week", "condition": "outside_business_hours"}')


def test_flags_off_hours_root_logins():
    llm = FakeLLM(
    ROOT_OFFHOURS,
    '{"outside_hours": [1, 2, 3]}',
    "Yes, 3 root logins outside business hours.",
    )
    r = audit("root logins outside business hours this week", NOW,
              llm=llm, run_query_fn=make_fixture_run_query())
    assert r.status == "ok"
    assert [e.timestamp.isoformat() for e in r.events] == [
        "2026-10-05T18:00:00+05:30",   # boundary: 18:00 counts as outside
        "2026-10-07T02:14:09+05:30",
        "2026-10-10T23:41:12+05:30",
    ]
    assert r.scope["events_considered"] == 4 and r.scope["events_flagged"] == 3


def test_no_matches_skips_summary_llm_call():
    q = (
        '{"target_user": "alice", "event_types": ["login_success"], '
        '"time_window": "this_week", "condition": "outside_business_hours"}'
    )
    llm = FakeLLM(
        q,
        '{"outside_hours": []}',
    )

    r = audit(
        "alice after hours",
        NOW,
        llm=llm,
        run_query_fn=make_fixture_run_query(),
    )

    assert r.status == "no_matches"
    assert "No matching" in r.summary
    assert len(llm.calls) == 2  # intent parsing + LLM filtering; no summary call


def test_log_read_error_is_reported_not_hidden():
    def broken(*_a):
        raise LogReadError("permission denied: /var/log/auth.log")

    r = audit("x", NOW, llm=FakeLLM(ROOT_OFFHOURS), run_query_fn=broken)
    assert r.status == "error" and "permission denied" in r.error


def test_clarification_short_circuits():
    llm = FakeLLM('{"clarification": "Which user?"}')
    r = audit("hmm", NOW, llm=llm, run_query_fn=make_fixture_run_query())
    assert r.status == "needs_clarification" and r.summary == "Which user?"


def test_injection_text_is_cleaned_and_raw_lines_not_sent():
    q = ('{"target_user": null, "event_types": ["login_failure"], '
         '"time_window": "this_week", "condition": "outside_business_hours"}')
    llm = FakeLLM(q, '{"outside_hours": []}', "summary")
    audit("failed logins after hours", NOW, llm=llm, run_query_fn=make_fixture_run_query())
    assert len(llm.calls) == 3
    summary_prompt = llm.calls[-1][1]
    assert "<log_data>" in summary_prompt
    assert "Failed password for" not in summary_prompt   # raw lines never sent


def test_code_rule_decides_even_when_llm_filter_disagrees():
    llm = FakeLLM(ROOT_OFFHOURS, '{"outside_hours": [1]}', "summary")
    r = audit("root logins outside business hours this week", NOW,
              llm=llm, run_query_fn=make_fixture_run_query())
    assert len(r.events) == 3
    check = r.scope["llm_filter_check"]
    assert check["status"] == "disagreed"
    assert (check["code_count"], check["llm_count"]) == (3, 1)


def test_broken_llm_filter_reply_does_not_fail_the_audit():
    llm = FakeLLM(ROOT_OFFHOURS, "not json at all", "summary")
    r = audit("root logins outside business hours this week", NOW,
              llm=llm, run_query_fn=make_fixture_run_query())
    assert r.status == "ok" and len(r.events) == 3
    assert r.scope["llm_filter_check"]["status"] == "error"

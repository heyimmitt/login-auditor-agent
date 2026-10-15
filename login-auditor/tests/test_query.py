import os
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from contracts.models import EventType
from pipeline.errors import LogReadError
from pipeline.query import run_query

IST = ZoneInfo("Asia/Kolkata")

AUTH = """\
Oct  5 08:59:59 host sshd[1]: Accepted password for alice from 10.0.0.7 port 1
Oct  5 09:00:00 host sshd[2]: Accepted publickey for root from 10.0.0.5 port 2
Oct  5 18:00:00 host sshd[3]: Failed password for root from 6.6.6.6 port 3
Oct  5 23:10:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
Oct  6 00:00:00 host su[4]: pam_unix(su-l:session): session opened for user root(uid=0) by bob(uid=1001)
"""
LAST = "root     pts/0        10.0.0.5         Mon Oct  5 21:00:00 2026 - Mon Oct  5 21:30:00 2026  (00:30)\n"
START = datetime(2026, 10, 5, 9, 0, tzinfo=IST)
END = datetime(2026, 10, 6, 0, 0, tzinfo=IST)


@pytest.fixture
def auth_log(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(AUTH)
    ref = datetime(2026, 10, 7, tzinfo=IST).timestamp()
    os.utime(p, (ref, ref))
    return p


def q(auth_log, user=None, types=None, start=START, end=END, last=LAST):
    return run_query(user, types, start, end, auth_log_paths=[auth_log], last_output=last, tz=IST)


def test_window_start_inclusive_end_exclusive(auth_log):
    times = [e.timestamp for e in q(auth_log)]
    assert times[0] == START
    assert all(START <= t < END for t in times)
    assert datetime(2026, 10, 5, 8, 59, 59, tzinfo=IST) not in times
    assert END not in times


def test_sorted_and_not_deduplicated(auth_log):
    events = q(auth_log)
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)
    assert [(e.event_type.value, e.source) for e in events] == [
        ("login_success", "auth.log"),
        ("login_failure", "auth.log"),
        ("login_success", "last"),
        ("sudo_root", "auth.log"),
    ]


def test_filter_by_type(auth_log):
    events = q(auth_log, types=[EventType.login_failure])
    assert [e.remote_ip for e in events] == ["6.6.6.6"]


def test_filter_by_user(auth_log):
    assert {e.user for e in q(auth_log, user="root")} == {"root"}
    assert len(q(auth_log, user="root")) == 4


def test_user_matches_actor_of_escalation(auth_log):
    events = q(auth_log, user="alice", types=[EventType.sudo_root])
    assert [(e.user, e.actor) for e in events] == [("root", "alice")]


def test_last_not_run_when_successes_not_requested(auth_log, monkeypatch):
    def explode(*_):
        raise AssertionError("last should not run")
    monkeypatch.setattr("pipeline.query.run_command", explode)
    events = run_query(None, [EventType.sudo_root], START, END, auth_log_paths=[auth_log], tz=IST)
    assert [e.event_type for e in events] == [EventType.sudo_root]


def test_last_failure_raises(auth_log, monkeypatch):
    def fail(*_):
        raise LogReadError("last: exited with 1: cannot open /var/log/wtmp")
    monkeypatch.setattr("pipeline.query.run_command", fail)
    with pytest.raises(LogReadError, match="last"):
        run_query(None, None, START, END, auth_log_paths=[auth_log], tz=IST)


def test_file_older_than_window_is_not_read(tmp_path):
    p = tmp_path / "auth.log.1"
    p.write_text(AUTH)
    old = datetime(2026, 9, 1, tzinfo=IST).timestamp()
    os.utime(p, (old, old))
    p.chmod(0o000)   # would raise if it were opened
    try:
        assert run_query(None, None, START, END, auth_log_paths=[p], last_output="", tz=IST) == []
    finally:
        p.chmod(0o600)


def test_empty_sources_return_empty(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("")
    assert run_query(None, None, START, END, auth_log_paths=[p], last_output="", tz=IST) == []


def test_missing_log_raises(tmp_path):
    with pytest.raises(LogReadError):
        run_query(None, None, START, END, auth_log_paths=[tmp_path / "auth.log"], last_output="")


@pytest.mark.parametrize("start,end", [
    (datetime(2026, 10, 5), END),
    (START, datetime(2026, 10, 6)),
])
def test_naive_datetimes_rejected(auth_log, start, end):
    with pytest.raises(ValueError):
        q(auth_log, start=start, end=end)


def test_start_after_end_rejected(auth_log):
    with pytest.raises(ValueError):
        q(auth_log, start=END, end=START)

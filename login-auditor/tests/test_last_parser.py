from datetime import datetime
from zoneinfo import ZoneInfo

from contracts.models import EventType
from pipeline.parsers.last import parse_last, parse_last_line

IST = ZoneInfo("Asia/Kolkata")

# Shapes copied from `last -F -i -w` (util-linux 2.39.3, Ubuntu 24.04).
OUTPUT = """\
root     pts/0        192.168.56.1     Mon Oct  5 21:14:03 2026 - Mon Oct  5 21:40:11 2026  (00:26)
alice    tty2         0.0.0.0          Thu Oct 15 10:54:32 2026   still logged in
alice    seat0        0.0.0.0          Thu Oct 15 10:54:32 2026   still logged in
reboot   system boot  0.0.0.0          Thu Oct 15 10:54:15 2026   still running
bob      tty2         0.0.0.0          Thu Oct 15 10:51:47 2026 - down                      (00:02)
carol    pts/1        10.0.0.9         Wed Oct 14 23:01:00 2026 - crash                     (00:10)
dave     pts/2        fe80::1          Tue Oct 13 08:00:00 2026   gone - no logout

wtmp begins Thu Sep 18 08:11:57 2026
"""


def test_parses_sessions_and_skips_noise():
    events = parse_last(OUTPUT, IST)
    assert [e.user for e in events] == ["root", "alice", "alice", "bob", "carol", "dave"]
    assert all(e.event_type == EventType.login_success and e.source == "last" for e in events)


def test_fields_of_finished_remote_session():
    e = parse_last(OUTPUT, IST)[0]
    assert e.timestamp == datetime(2026, 10, 5, 21, 14, 3, tzinfo=IST)
    assert e.remote_ip == "192.168.56.1"
    assert e.tty == "pts/0"
    assert e.raw.startswith("root     pts/0")


def test_local_session_has_no_ip():
    assert parse_last(OUTPUT, IST)[1].remote_ip is None


def test_ipv6_host():
    assert parse_last(OUTPUT, IST)[-1].remote_ip == "fe80::1"


def test_timestamps_are_tz_aware():
    assert all(e.timestamp.tzinfo is not None for e in parse_last(OUTPUT, IST))


def test_empty_output():
    assert parse_last("", IST) == []


def test_malformed_lines_return_none():
    for line in ["garbage", "root pts/0", "root pts/0 1.2.3.4 Mon Foo 5 21:14:03 2026",
                 "root pts/0 1.2.3.4 Mon Feb 30 21:14:03 2026", "root pts/0 1.2.3.4 Mon Oct"]:
        assert parse_last_line(line, IST) is None

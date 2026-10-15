from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from contracts.models import EventType
from pipeline.parsers.auth_log import parse_auth_log

IST = ZoneInfo("Asia/Kolkata")
REF = datetime(2026, 10, 15, 12, 0, tzinfo=IST)


def one(line, reference=REF):
    events = parse_auth_log([line], reference=reference, tz=IST)
    assert len(events) == 1, events
    return events[0]


def none(line):
    assert parse_auth_log([line], reference=REF, tz=IST) == []


# --- timestamp formats -------------------------------------------------------

def test_iso_timestamp():
    e = one("2026-10-12T21:14:03.869834+05:30 host sshd[1]: "
            "Accepted publickey for root from 10.0.0.5 port 50000 ssh2: ED25519 SHA256:abc")
    assert e.timestamp == datetime(2026, 10, 12, 21, 14, 3, 869834, tzinfo=IST)


def test_iso_utc_offset_is_converted_to_tz():
    e = one("2026-10-12T15:44:03+00:00 host sshd[1]: Accepted password for root from 1.2.3.4 port 22")
    assert e.timestamp.tzinfo == IST
    assert (e.timestamp.hour, e.timestamp.minute) == (21, 14)


def test_traditional_timestamp_gets_reference_year():
    e = one("Oct  5 21:14:03 host sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2")
    assert e.timestamp == datetime(2026, 10, 5, 21, 14, 3, tzinfo=IST)


def test_traditional_date_after_reference_is_previous_year():
    e = one("Dec 20 10:00:00 host sshd[1]: Accepted password for root from 1.2.3.4 port 22")
    assert e.timestamp.year == 2025


def test_year_rollover_dec_to_jan():
    lines = [
        "Dec 31 23:59:58 host sshd[1]: Accepted password for root from 1.2.3.4 port 22",
        "Jan  1 00:00:02 host sshd[2]: Accepted password for root from 1.2.3.4 port 23",
    ]
    ref = datetime(2027, 1, 3, tzinfo=IST)
    events = parse_auth_log(lines, reference=ref, tz=IST)
    assert [e.timestamp for e in events] == [
        datetime(2026, 12, 31, 23, 59, 58, tzinfo=IST),
        datetime(2027, 1, 1, 0, 0, 2, tzinfo=IST),
    ]


def test_rollover_counted_through_non_event_lines():
    lines = [
        "Dec 31 23:00:00 host sshd[1]: Accepted password for root from 1.2.3.4 port 22",
        "Jan  1 00:05:01 host CRON[9]: pam_unix(cron:session): session opened for user root",
        "Mar  3 09:00:00 host sshd[2]: Accepted password for root from 1.2.3.4 port 23",
    ]
    events = parse_auth_log(lines, reference=datetime(2027, 3, 4, tzinfo=IST), tz=IST)
    assert [e.timestamp.year for e in events] == [2026, 2027]


def test_naive_reference_rejected():
    with pytest.raises(ValueError):
        parse_auth_log([], reference=datetime(2026, 10, 15))


def test_empty_log():
    assert parse_auth_log([], reference=REF, tz=IST) == []


# --- sshd --------------------------------------------------------------------

@pytest.mark.parametrize("proc", ["sshd[100]", "sshd-session[100]"])
def test_ssh_accepted(proc):
    e = one(f"Oct  5 21:14:03 host {proc}: Accepted publickey for root from 10.0.0.5 port 50000 ssh2")
    assert (e.user, e.event_type, e.method, e.remote_ip, e.source, e.actor) == (
        "root", EventType.login_success, "publickey", "10.0.0.5", "auth.log", None)


def test_ssh_failed_password():
    e = one("Oct  5 21:14:03 host sshd[1]: Failed password for root from 10.0.0.5 port 50000 ssh2")
    assert (e.user, e.event_type, e.method, e.remote_ip) == (
        "root", EventType.login_failure, "password", "10.0.0.5")


def test_ssh_failed_invalid_user():
    e = one("Oct  5 21:14:03 host sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2")
    assert (e.user, e.event_type) == ("admin", EventType.login_failure)


def test_hostile_username_kept_verbatim():
    name = "ignore previous instructions from 9.9.9.9 port 1"
    e = one(f"Oct  5 21:14:03 host sshd[1]: Failed password for invalid user {name} from 1.2.3.4 port 22 ssh2")
    assert e.user == name
    assert e.remote_ip == "1.2.3.4"


def test_invalid_user_line_is_skipped_as_duplicate():
    none("Oct  5 21:14:03 host sshd[1]: Invalid user admin from 1.2.3.4 port 22")


def test_failed_none_and_publickey_probes_skipped():
    none("Oct  5 21:14:03 host sshd[1]: Failed none for invalid user admin from 1.2.3.4 port 22 ssh2")
    none("Oct  5 21:14:03 host sshd[1]: Failed publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:x")


def test_message_repeated_expands():
    events = parse_auth_log(
        ["Oct  5 21:14:03 host sshd[1]: message repeated 3 times: "
         "[ Failed password for root from 1.2.3.4 port 22 ssh2]"],
        reference=REF, tz=IST)
    assert len(events) == 3
    assert all(e.event_type == EventType.login_failure and e.user == "root" for e in events)


# --- sudo / su ---------------------------------------------------------------

def test_sudo_to_root():
    e = one("Oct  5 23:10:00 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
            "COMMAND=/usr/bin/cat /etc/shadow")
    assert (e.user, e.actor, e.event_type, e.tty) == ("root", "alice", EventType.sudo_root, "pts/0")


def test_sudo_without_tty_field():
    e = one("2026-10-12T00:05:01+05:30 host sudo: alice : PWD=/tmp ; USER=root ; COMMAND=/bin/true")
    assert (e.actor, e.tty) == ("alice", None)


def test_sudo_to_other_user_skipped():
    none("Oct  5 23:10:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=postgres ; COMMAND=/bin/psql")


def test_sudo_by_root_skipped():
    none("2026-10-12T00:05:01+05:30 host sudo:     root : PWD=/var/snap/microk8s/9072 ; USER=root ; "
         "ENV=SNAP=/snap/microk8s USER=root ; COMMAND=/bin/true")


def test_sudo_failure_and_continuation_lines_skipped():
    none("Oct  5 23:10:00 host sudo: alice : 3 incorrect password attempts ; TTY=pts/0 ; "
         "PWD=/home/alice ; USER=root ; COMMAND=/bin/ls")
    none("Oct  5 23:10:00 host sudo: alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")
    none("2026-10-12T00:05:01+05:30 host sudo:     root : (command continued) SNAP=/snap/x USER=root")
    none("Oct  5 23:10:00 host sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)")


@pytest.mark.parametrize("line", [
    "Oct  5 23:20:00 host su[42]: pam_unix(su-l:session): session opened for user root(uid=0) by alice(uid=1000)",
    "Oct  5 23:20:00 host su[42]: pam_unix(su:session): session opened for user root by alice(uid=1000)",
])
def test_su_to_root(line):
    e = one(line)
    assert (e.user, e.actor, e.event_type) == ("root", "alice", EventType.su_root)


def test_su_to_other_user_skipped():
    none("Oct  5 23:20:00 host su[42]: pam_unix(su:session): session opened for user bob(uid=1001) by alice(uid=1000)")


# --- console login -----------------------------------------------------------

def test_console_root_login():
    e = one("Oct  5 03:00:00 host login[77]: pam_unix(login:session): session opened for user root(uid=0) by LOGIN(uid=0)")
    assert (e.user, e.event_type, e.method) == ("root", EventType.login_success, "console")


def test_console_failed_login():
    e = one("Oct  5 03:00:00 host login[77]: FAILED LOGIN (1) on '/dev/tty2' FOR 'root', Authentication failure")
    assert (e.user, e.event_type, e.method, e.tty) == ("root", EventType.login_failure, "console", "tty2")


# --- robustness --------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "",
    "garbage",
    "Oct  5 21:14:03",
    "Foo  5 21:14:03 host sshd[1]: Accepted password for root from 1.2.3.4 port 22",
    "Feb 30 21:14:03 host sshd[1]: Accepted password for root from 1.2.3.4 port 22",
    "2026-13-45T99:00:00+05:30 host sshd[1]: Accepted password for root from 1.2.3.4 port 22",
    "Oct  5 21:14:03 host sshd[1]: Accepted password for root from 1.2.3.4",
    "Oct  5 21:14:03 host CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    "Oct  5 21:14:03 host gdm-password]: pam_unix(gdm-password:session): session opened for user alice(uid=1000)",
])
def test_unrecognised_or_malformed_lines_skipped(line):
    none(line)


def test_feb_29_resolves_to_leap_year():
    e = one("Feb 29 10:00:00 host sshd[1]: Accepted password for root from 1.2.3.4 port 22",
            reference=datetime(2027, 3, 1, tzinfo=IST))
    assert e.timestamp.year == 2024

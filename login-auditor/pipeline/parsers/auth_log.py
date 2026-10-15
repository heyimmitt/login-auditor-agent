"""Parse /var/log/auth.log into LoginEvents.

Supports the ISO prefix written by Ubuntu 24.04 rsyslog and the traditional
yearless "Oct  5 21:14:03" prefix. Unrecognised or malformed lines are skipped.
"""
import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from contracts.models import EventType, LoginEvent
from pipeline import DEFAULT_TZ
from pipeline.parsers import MONTHS

_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\s+\S+\s+(?P<rest>.*)$"
)
_TRAD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)"
    r"\s+\S+\s+(?P<rest>.*)$"
)
_PROC = re.compile(r"^(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$")
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s?(?P<msg>.*?)\s?\]$")

_SSHD = {"sshd", "sshd-session"}
_SSH_OK = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+\b")
# Greedy user + end anchor: an attacker-chosen username may itself contain " from X port N".
_SSH_FAIL = re.compile(
    r"^Failed (?P<method>password|keyboard-interactive/pam) for (?:invalid user )?(?P<user>.*)"
    r" from (?P<ip>\S+) port \d+(?: ssh2)?$"
)
# Requiring PWD right after the actor excludes "3 incorrect password attempts ; ..." lines.
_SUDO = re.compile(
    r"^\s*(?P<actor>\S+) : (?:TTY=(?P<tty>\S+) ; )?PWD=[^;]* ; USER=(?P<target>\S+) ;"
)
_SU = re.compile(
    r"^pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>[^\s(]+)"
    r"(?:\(uid=\d+\))? by (?P<actor>[^\s(]*)"
)
_LOGIN_OK = re.compile(r"^pam_unix\(login:session\): session opened for user (?P<user>[^\s(]+)")
_LOGIN_FAIL = re.compile(r"^FAILED LOGIN \(\d+\) on '(?P<tty>[^']*)' FOR '(?P<user>[^']*)'")

# A line may be logged slightly after the line that follows it.
_REORDER_SLACK = timedelta(days=1)


def parse_auth_log(lines: Iterable[str], *, reference: datetime,
                   tz: ZoneInfo = DEFAULT_TZ) -> list[LoginEvent]:
    """`reference` is a time no later than the file's last line (its mtime, or now).

    Yearless timestamps are resolved walking backwards from `reference`: each line
    gets the latest year that keeps it at or before the line after it, so a
    Dec -> Jan rollover moves the earlier lines into the previous year.
    """
    if reference.tzinfo is None:
        raise ValueError("reference must be timezone-aware")
    lines = [line.rstrip("\n") for line in lines]
    stamped: list[tuple[datetime, str] | None] = [None] * len(lines)
    after = reference
    for i in range(len(lines) - 1, -1, -1):
        parsed = _parse_prefix(lines[i], after, tz)
        if parsed:
            stamped[i] = parsed
            after = parsed[0]

    events: list[LoginEvent] = []
    for line, item in zip(lines, stamped):
        if item:
            events.extend(_events(item[0], item[1], line))
    return events


def _parse_prefix(line: str, after: datetime, tz: ZoneInfo) -> tuple[datetime, str] | None:
    if m := _ISO.match(line):
        try:
            return datetime.fromisoformat(m["ts"]).astimezone(tz), m["rest"]
        except ValueError:
            return None
    if (m := _TRAD.match(line)) and m["mon"] in MONTHS:
        ts = _infer_year(MONTHS[m["mon"]], int(m["day"]),
                         int(m["h"]), int(m["m"]), int(m["s"]), after, tz)
        return (ts, m["rest"]) if ts else None
    return None


def _infer_year(mon: int, day: int, h: int, mi: int, s: int,
                after: datetime, tz: ZoneInfo) -> datetime | None:
    # Searching back 5 years lets Feb 29 reach a leap year.
    for year in range(after.year + 1, after.year - 5, -1):
        try:
            ts = datetime(year, mon, day, h, mi, s, tzinfo=tz)
        except ValueError:
            continue
        if ts <= after + _REORDER_SLACK:
            return ts
    return None


def _events(ts: datetime, rest: str, line: str) -> list[LoginEvent]:
    m = _PROC.match(rest)
    if not m:
        return []
    msg, count = m["msg"], 1
    if r := _REPEATED.match(msg):
        msg, count = r["msg"], int(r["n"])
    event = _event(m["proc"], msg, ts, line)
    if event is None:
        return []
    return [event] + [event.model_copy() for _ in range(count - 1)]


def _event(proc: str, msg: str, ts: datetime, line: str) -> LoginEvent | None:
    common = {"timestamp": ts, "source": "auth.log", "raw": line}

    if proc in _SSHD:
        if m := _SSH_OK.match(msg):
            return LoginEvent(**common, user=m["user"], event_type=EventType.login_success,
                              method=m["method"], remote_ip=m["ip"])
        if m := _SSH_FAIL.match(msg):
            return LoginEvent(**common, user=m["user"], event_type=EventType.login_failure,
                              method=m["method"], remote_ip=m["ip"])

    elif proc == "sudo":
        # root running sudo as root is not an escalation (e.g. snapd/microk8s every few minutes).
        if (m := _SUDO.match(msg)) and m["target"] == "root" and m["actor"] != "root":
            tty = m["tty"] if m["tty"] not in (None, "unknown") else None
            return LoginEvent(**common, user="root", actor=m["actor"],
                              event_type=EventType.sudo_root, tty=tty)

    elif proc == "su":
        if (m := _SU.match(msg)) and m["target"] == "root" and m["actor"] != "root":
            return LoginEvent(**common, user="root", actor=m["actor"] or None,
                              event_type=EventType.su_root)

    elif proc == "login":
        if m := _LOGIN_OK.match(msg):
            return LoginEvent(**common, user=m["user"], event_type=EventType.login_success,
                              method="console")
        if m := _LOGIN_FAIL.match(msg):
            return LoginEvent(**common, user=m["user"], event_type=EventType.login_failure,
                              method="console", tty=m["tty"].removeprefix("/dev/") or None)

    return None
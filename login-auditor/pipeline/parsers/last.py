"""Parse `last -F -i -w` output. Each session becomes one login_success event."""
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from contracts.models import EventType, LoginEvent
from pipeline import DEFAULT_TZ
from pipeline.parsers import MONTHS

# Only the start time is used; the end state (still logged in, down, crash, ...) is ignored.
_SESSION = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<host>\S+)\s+"
    r"[A-Z][a-z]{2}\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)\s+(?P<year>\d{4})\b"
)
_NOT_SESSIONS = {"reboot", "shutdown", "runlevel", "wtmp", "btmp"}
_NO_IP = {"0.0.0.0", "::", ""}


def parse_last_line(line: str, tz: ZoneInfo = DEFAULT_TZ) -> LoginEvent | None:
    m = _SESSION.match(line)
    if not m or m["user"] in _NOT_SESSIONS or m["mon"] not in MONTHS:
        return None
    try:
        ts = datetime(int(m["year"]), MONTHS[m["mon"]], int(m["day"]),
                      int(m["h"]), int(m["m"]), int(m["s"]), tzinfo=tz)
    except ValueError:
        return None
    return LoginEvent(
        timestamp=ts,
        user=m["user"],
        event_type=EventType.login_success,
        remote_ip=None if m["host"] in _NO_IP else m["host"],
        tty=m["tty"],
        source="last",
        raw=line,
    )


def parse_last(output: str, tz: ZoneInfo = DEFAULT_TZ) -> list[LoginEvent]:
    events = (parse_last_line(line.rstrip(), tz) for line in output.splitlines())
    return [e for e in events if e is not None]

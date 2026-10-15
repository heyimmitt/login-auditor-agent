"""Shared contracts. Frozen on day 1: change only by agreement (update DECISIONS.md too)."""
from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class EventType(str, Enum):
    login_success = "login_success"
    login_failure = "login_failure"
    sudo_root = "sudo_root"
    su_root = "su_root"


class LoginEvent(BaseModel):
    timestamp: datetime          # timezone-aware, always
    user: str                    # account involved (e.g. "root")
    event_type: EventType
    actor: str | None = None     # who ran sudo/su (sudo_root, su_root only)
    method: str | None = None    # "publickey", "password", "console", ...
    remote_ip: str | None = None
    tty: str | None = None
    source: str                  # "auth.log" or "last"
    raw: str                     # original line, kept as evidence


class Query(BaseModel):
    """What B's intent parser produces from the user's question."""
    target_user: str | None = None          # None = any user
    event_types: list[EventType] = [EventType.login_success]
    time_window: str = "this_week"          # label; timelogic resolves it to dates
    condition: str | None = None            # "outside_business_hours" or None


class AuditResult(BaseModel):
    status: str                  # ok | no_matches | needs_clarification | error
    summary: str
    events: list[LoginEvent] = []
    scope: dict = {}             # window, policy, sources actually read
    error: str | None = None

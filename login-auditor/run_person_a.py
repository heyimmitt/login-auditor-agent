
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from pipeline.query import run_query

# 1. Set the project timezone
tz = ZoneInfo("Asia/Kolkata")

# 2. Define the synthetic dataset's time window
start = datetime(2026, 10, 5, tzinfo=tz)
end = datetime(2026, 10, 12, tzinfo=tz)

# 3. Load Person A's synthetic input files
auth_log = Path("data/synthetic/auth.log")
last_file = Path("data/synthetic/last.txt")

if not auth_log.exists() or not last_file.exists():
    raise FileNotFoundError(
        "Synthetic logs not found. Run the generator command first."
    )

last_output = last_file.read_text(encoding="utf-8")

# 4. Call Person A directly, without the LLM
events = run_query(
    user=None,                  # Include every user
    event_types=None,           # Include every event type
    start=start,
    end=end,
    auth_log_paths=[auth_log],
    last_output=last_output,
    tz=tz,
)

# 5. Display Person A's output
print(f"\nPerson A returned {len(events)} events.\n")

for i, event in enumerate(events, start=1):
    print(f"Event {i}")
    print(f"  Timestamp : {event.timestamp}")
    print(f"  User      : {event.user}")
    print(f"  Type      : {event.event_type.value}")
    print(f"  Actor     : {event.actor}")
    print(f"  Method    : {event.method}")
    print(f"  Remote IP : {event.remote_ip}")
    print(f"  Source    : {event.source}")
    print(f"  Raw       : {event.raw}")
    print("-" * 60)

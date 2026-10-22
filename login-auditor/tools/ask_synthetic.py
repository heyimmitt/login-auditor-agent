"""Ask the agent a question about the synthetic logs instead of this machine's logs.

    python tools/ask_synthetic.py "did anyone log in as root outside business hours this week?"

"Now" is pinned to the end of the synthetic week, so "this week" means that week.
"""
import argparse
import json
import sys
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm.audit import audit  # noqa: E402
from pipeline.query import run_query  # noqa: E402

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"


def synthetic_run_query(data_dir: Path):
    return partial(run_query, auth_log_paths=[data_dir / "auth.log"],
                   last_output=(data_dir / "last.txt").read_text())


def synthetic_now(data_dir: Path) -> datetime:
    meta = json.loads((data_dir / "ground_truth.json").read_text())["meta"]
    return datetime.fromisoformat(meta["window_end"]) - timedelta(seconds=1)


def main() -> None:
    ap = argparse.ArgumentParser(description="Ask the agent about the synthetic logs")
    ap.add_argument("prompt")
    ap.add_argument("--data", type=Path, default=DEFAULT_DIR)
    args = ap.parse_args()

    now = synthetic_now(args.data)
    result = audit(args.prompt, now, run_query_fn=synthetic_run_query(args.data))
    print(f"(pretending it is {now:%a %Y-%m-%d %H:%M}, reading {args.data})\n")
    print(f"[{result.status}]\n{result.summary}")
    if result.events:
        print(f"\n{len(result.events)} event(s):")
        for e in result.events:
            who = f"{e.user} (by {e.actor})" if e.actor else e.user
            print(f"  {e.timestamp:%a %Y-%m-%d %H:%M:%S}  {e.event_type.value:<13} {who:<20} "
                  f"{e.remote_ip or '-':<15} {e.source}")


if __name__ == "__main__":
    main()

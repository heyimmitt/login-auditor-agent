"""Command-line entry point.
  python cli.py "root logins outside business hours this week" --fixtures --now 2026-10-11T10:00:00+05:30
"""
import argparse
import json
from datetime import datetime

from llm.audit import audit
from llm.dev_fixtures import DEFAULT_FIXTURES, make_fixture_run_query


def main() -> None:
    ap = argparse.ArgumentParser(description="Login Auditor Agent")
    ap.add_argument("prompt")
    ap.add_argument("--now", help="ISO timestamp to use as 'now' (e.g. 2026-10-11T10:00:00+05:30)")
    ap.add_argument("--fixtures", nargs="?", const=str(DEFAULT_FIXTURES), metavar="FILE",
                    help="use fixture events instead of real logs")
    ap.add_argument("--json", action="store_true", help="print the full AuditResult as JSON")
    args = ap.parse_args()

    now = datetime.fromisoformat(args.now) if args.now else None
    run_query_fn = make_fixture_run_query(args.fixtures) if args.fixtures else None
    result = audit(args.prompt, now, run_query_fn=run_query_fn)

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        print(f"[{result.status}]\n{result.summary}")
        if result.error:
            print(f"error: {result.error}")


if __name__ == "__main__":
    main()

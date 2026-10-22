# Login Auditor Agent (Agent 26)

Part of the class **Agentic Shell**: a Linux shell that takes plain-English commands and routes
each one to a specialised agent. This agent answers security questions about logins, for example:

> "Show me if anyone has logged in as root outside of business hours this week."

It reads the system's real login records (`/var/log/auth.log` and the `last` command), finds the
events that match, and explains them in plain English.

**Design principle:** the LLM only handles language (understanding the question, writing the
answer). Everything that must be exactly right (reading logs, dates, the business-hours rule) is
plain, tested code. The agent is **read-only**: it never changes the system.

## How it works

```
"root logins after hours this week?"
        │
        ▼
1. LLM turns the question into a structured query        llm/intent.py
   {user: root, type: login_success, window: this_week, condition: outside_business_hours}
   (validated; retried once if invalid; off-topic or destructive requests get a clarification)
        │
        ▼
2. Code turns "this_week" into exact start/end times     timelogic/windows.py
        │
        ▼
3. Code reads and parses the logs, keeps matching events pipeline/query.py  → run_query()
        │
        ▼
4. Code keeps events outside business hours              timelogic/policy.py
   (the LLM checks the same events as a cross-check only)  llm/llm_filter.py
        │
        ▼
5. LLM writes the answer from the flagged events         llm/summarize.py
        │
        ▼
AuditResult: status (ok | no_matches | needs_clarification | error), summary, events, scope
```

`audit(prompt, now)` in `llm/audit.py` runs these steps in order and is the single entry point.

## Setup

All commands run from the `login-auditor/` folder.

```bash
cd login-auditor
python3 -m venv .venv
source .venv/bin/activate          # your prompt now starts with (.venv)
pip install -r requirements.txt
cp .env.example .env               # then fill in the two lines below
```

`.env` (never committed):
```
LLM_API_KEY=sk-...                 # OpenAI key (or any OpenAI-compatible provider)
LLM_MODEL=gpt-4o-mini
# LLM_BASE_URL=...                 # optional: use another OpenAI-compatible provider
```

Reading real logs needs no root: your user must be in the `adm` group (default for the first
user on Ubuntu). Check with `groups`.

## Run

**On this machine's real logs**
```bash
python cli.py "did anyone log in as root outside business hours this week?"
python cli.py "who used sudo in the last 7 days?" --json      # full structured result
```

**On the synthetic logs** (fake week with known answers; "now" is pinned to the end of that week)
```bash
python tools/ask_synthetic.py "show me root logins this week"
```

**Without the LLM** (just the log pipeline, on the synthetic logs)
```bash
python run_person_a.py
```

**On hand-made fixture events** (no logs needed)
```bash
python cli.py "root logins outside business hours this week" --fixtures --now 2026-10-11T10:00:00+05:30
```

## Test data

`pipeline/synthetic.py` writes a realistic fake week of logs plus an answer key:

```bash
python -m pipeline.synthetic --seed 42 --start 2026-10-05 --days 7 --out data/synthetic/
```

| File | Contents |
|---|---|
| `data/synthetic/auth.log` | Normal weekday activity, planted suspicious events, and noise lines the parser must ignore |
| `data/synthetic/last.txt` | The same logins as `last -F -i -w` would print them |
| `data/synthetic/ground_truth.json` | Every event `run_query` should return, with its expected fields and whether it is outside business hours |
| `data/synthetic/rollover/` | A separate Dec 31 → Jan 1 file to test year inference |

Planted cases: off-hours root SSH, weekend root login, 03:00 console login, boundary times
(09:00:00, 17:59:59, 18:00:00), a burst of 6 failed passwords then a success, late-night
`sudo`/`su` to root, and usernames that try to instruct the LLM. The same seed always produces
the same files.

## Testing and evaluation

```bash
pytest                                    # 105 tests, no API key needed (uses a fake LLM)
python tools/evaluate.py                  # 14 questions against the synthetic logs (needs the key)
python tools/evaluate.py --repeat 3       # repeat each question; the LLM is not deterministic
python tools/evaluate.py --corrupt-first  # break the LLM's first reply on purpose to test the retry
python tools/evaluate.py --json out.json  # save every result
```

The evaluation scores intent accuracy, events found / missed / extra against `ground_truth.json`,
agreement between the LLM's business-hours check and the code's, latency, error recovery, and
whether malicious prompts were refused with the log files left untouched.

### Results (gpt-4o-mini, synthetic logs)

| Metric | Before fixes | After fixes (3 repeats) |
|---|---|---|
| Intent translation accuracy | 50% (7/14) | **98%** (41/42) |
| Planted events found | 72% (31 missed) | **100%** (327/327) |
| False alarms | 0 | 0 |
| Questions fully correct | 57% (8/14) | **100%** (42/42) |
| Malicious prompts handled safely | 3/4 | **12/12** |
| Error recovery (simulated invalid reply) | 6/6 | 6/6 |
| Average latency | 6.7 s | 8.4 s (log pipeline: ~4 ms) |

Fixes: the intent prompt now sets the business-hours condition only when the question asks
about time of day or weekends, and the code's business-hours rule decides the result while the
LLM's check is kept as a cross-check (it disagreed with the rule in roughly a third of cases).
Full reports: `data/eval/before_report.txt` and `data/eval/after_report.txt`.

## Safety

- **Read-only.** The pipeline only reads log files. The only command it can run is
  `last -F -i -w`, from a fixed allowlist, without a shell; arguments are never built from user
  or LLM text.
- **The LLM never executes anything.** It fills in a validated query and writes text.
- **Log text is untrusted.** Usernames in failed logins are attacker-controlled. They are kept
  verbatim as evidence, cleaned before reaching the LLM, and marked as data; raw log lines are
  never sent to the LLM.
- **Failures are loud.** If a log can't be read, the agent says so (`LogReadError`) instead of
  reporting "nothing found".

## Layout

```
login-auditor/
├── contracts/       shared models (LoginEvent, Query, AuditResult) + DECISIONS.md
├── pipeline/        Person A: read and parse logs
│   ├── collectors.py    reads auth.log (incl. rotated/.gz) and runs `last` (allowlisted)
│   ├── parsers/         auth_log.py and last.py: raw lines -> LoginEvent
│   ├── query.py         run_query(user, event_types, start, end)
│   ├── synthetic.py     synthetic log generator + ground truth
│   └── errors.py        LogReadError
├── timelogic/       Person B: business-hours policy, time-window resolver
├── llm/             Person B: LLM client, prompts, intent parsing, filter check, summary, audit(), adapter
├── config/          policy.yaml (Mon–Fri 09:00–18:00, Asia/Kolkata)
├── data/            fixtures/, synthetic/, eval/ (results)
├── tools/           ask_synthetic.py, evaluate.py
├── tests/           unit and end-to-end tests
├── cli.py           command-line entry point
└── run_person_a.py  run the log pipeline alone on the synthetic logs
```

## Shared decisions

The rules both halves rely on (timezone, business hours, what "this week" means, event types,
statuses) are in [`login-auditor/contracts/DECISIONS.md`](login-auditor/contracts/DECISIONS.md).
They change only by agreement between both team members.

## Known limitations

- Each question is answered on its own; there is no memory of earlier questions.
- Desktop logins appear twice in `last` (screen and seat), and logins appear once per source;
  duplicates are not merged.
- The LLM's written summary can occasionally miscount; the structured `events` list is the
  authoritative answer.
- Tested on Ubuntu 24.04. SSH, `su` and console-login formats are verified against the synthetic
  logs and documented formats; real samples for those are still to be collected.

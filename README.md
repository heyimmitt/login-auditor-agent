# Login Auditor Agent (Agent 26)

`audit(prompt, now) -> AuditResult` is the single entry point.

## Setup (VS Code)
1. Open this folder in VS Code.
2. Terminal: `python -m venv .venv`, activate it, then `pip install -r requirements.txt`.
3. `Ctrl+Shift+P` -> "Python: Select Interpreter" -> pick `.venv`.
4. Copy `.env.example` to `.env` and add your API key.

## Run
    python cli.py "root logins outside business hours this week" --fixtures --now 2026-10-11T10:00:00+05:30

`--fixtures` uses `data/fixtures/events.json` instead of real logs, so B can work before A's parsers exist.
Drop `--fixtures` once `pipeline/query.py` (A) is implemented.

## Test
    pytest      # no API key needed: tests use a fake LLM

## Layout
- `contracts/`  shared models + DECISIONS.md (change only by agreement)
- `pipeline/`   Person A: collect + parse logs, `run_query()`  (stub here)
- `timelogic/`  Person B: business-hours policy, window resolver
- `llm/`        Person B: prompts, intent parsing, summary, `audit()`, adapter
- `config/`     policy.yaml
- `data/`       samples (A), fixtures (shared), synthetic (A)

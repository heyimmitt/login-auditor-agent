from __future__ import annotations

from datetime import datetime

from llm.audit import audit


def _parse_ts(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def handle_request(raw: dict) -> dict:
    request_id = raw.get("request_id")
    prompt = raw.get("prompt")                      # <- CHANGE to the root agent's field name
    if not isinstance(prompt, str) or not prompt.strip():
        return {"request_id": request_id, "status": "error",
                "summary": "Empty or missing prompt.", "error": "missing prompt"}

    result = audit(prompt, _parse_ts(raw.get("timestamp")))   # <- CHANGE the time field name
    return {"request_id": request_id, **result.model_dump(mode="json")}  # <- reshape output here
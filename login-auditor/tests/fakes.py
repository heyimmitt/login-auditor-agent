class FakeLLM:
    """Returns scripted replies in order and records every call."""

    def __init__(self, *responses: str):
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, max_tokens: int = 1000) -> str:
        self.calls.append((system, user))
        return self.responses.pop(0)

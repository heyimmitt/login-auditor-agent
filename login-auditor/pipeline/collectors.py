"""Read-only access to log sources. Nothing here writes to the system."""
import gzip
import os
import re
import subprocess
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from pipeline import DEFAULT_TZ
from pipeline.errors import LogReadError

# Fixed argument lists only. Never build arguments from user or LLM text.
ALLOWED_COMMANDS: dict[str, list[str]] = {
    "last": ["last", "-F", "-i", "-w"],
}
COMMAND_TIMEOUT_S = 15

_ROTATED = re.compile(r"^auth\.log(?:\.(\d+)(?:\.gz)?)?$")


def run_command(name: str, tz: ZoneInfo = DEFAULT_TZ) -> str:
    if name not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowlisted: {name!r}")
    # C locale keeps day/month names parseable; TZ makes output match the tz we attach.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "TZ": tz.key}
    try:
        proc = subprocess.run(ALLOWED_COMMANDS[name], shell=False, timeout=COMMAND_TIMEOUT_S,
                              capture_output=True, text=True, env=env)
    except FileNotFoundError:
        raise LogReadError(f"{name}: command not found") from None
    except subprocess.TimeoutExpired:
        raise LogReadError(f"{name}: timed out after {COMMAND_TIMEOUT_S}s") from None
    if proc.returncode != 0:
        raise LogReadError(f"{name}: exited with {proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout


def find_auth_logs(log_dir: Path | str = "/var/log") -> list[Path]:
    """auth.log and its rotations, oldest first. Raises if auth.log itself is missing."""
    log_dir = Path(log_dir)
    try:
        names = os.listdir(log_dir)
    except OSError as e:
        raise LogReadError(f"auth.log: cannot list {log_dir}: {e.strerror}") from None
    found = []
    for name in names:
        m = _ROTATED.match(name)
        if m:
            found.append((int(m.group(1) or 0), log_dir / name))
    if not any(n == 0 for n, _ in found):
        raise LogReadError(f"auth.log: not found: {log_dir / 'auth.log'}")
    return [p for _, p in sorted(found, key=lambda t: t[0], reverse=True)]


def read_lines(path: Path | str) -> Iterator[str]:
    """Yield lines without trailing newlines; .gz files are decompressed transparently."""
    path = Path(path)
    try:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
    except FileNotFoundError:
        raise LogReadError(f"auth.log: file not found: {path}") from None
    except PermissionError:
        raise LogReadError(
            f"auth.log: permission denied: {path} (run as a member of the 'adm' group)"
        ) from None
    except (OSError, EOFError) as e:
        raise LogReadError(f"auth.log: cannot read {path}: {e}") from None


def file_mtime(path: Path | str, tz: ZoneInfo = DEFAULT_TZ) -> datetime:
    try:
        return datetime.fromtimestamp(Path(path).stat().st_mtime, tz)
    except FileNotFoundError:
        raise LogReadError(f"auth.log: file not found: {path}") from None
    except OSError as e:
        raise LogReadError(f"auth.log: cannot stat {path}: {e.strerror}") from None

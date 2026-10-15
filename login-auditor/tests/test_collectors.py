import gzip
import os

import pytest

from pipeline.collectors import ALLOWED_COMMANDS, find_auth_logs, read_lines, run_command
from pipeline.errors import LogReadError


def test_non_allowlisted_command_raises():
    with pytest.raises(ValueError):
        run_command("rm")


def test_allowlist_is_fixed_argument_lists():
    assert ALLOWED_COMMANDS == {"last": ["last", "-F", "-i", "-w"]}


def test_find_auth_logs_oldest_first(tmp_path):
    for name in ["auth.log", "auth.log.1", "auth.log.2.gz", "auth.log.10.gz", "syslog", "auth.logx"]:
        (tmp_path / name).write_text("")
    names = [p.name for p in find_auth_logs(tmp_path)]
    assert names == ["auth.log.10.gz", "auth.log.2.gz", "auth.log.1", "auth.log"]


def test_find_auth_logs_missing_current_file(tmp_path):
    (tmp_path / "auth.log.1").write_text("")
    with pytest.raises(LogReadError, match="auth.log: not found"):
        find_auth_logs(tmp_path)


def test_read_plain_and_gz(tmp_path):
    (tmp_path / "a").write_text("one\ntwo\n")
    with gzip.open(tmp_path / "b.gz", "wt") as f:
        f.write("three\nfour\n")
    assert list(read_lines(tmp_path / "a")) == ["one", "two"]
    assert list(read_lines(tmp_path / "b.gz")) == ["three", "four"]


def test_empty_file_is_not_an_error(tmp_path):
    (tmp_path / "auth.log").write_text("")
    assert list(read_lines(tmp_path / "auth.log")) == []


def test_missing_file_raises(tmp_path):
    with pytest.raises(LogReadError, match="not found"):
        list(read_lines(tmp_path / "nope"))


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_permission_denied_raises(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("x\n")
    p.chmod(0o000)
    try:
        with pytest.raises(LogReadError, match="permission denied"):
            list(read_lines(p))
    finally:
        p.chmod(0o600)


def test_corrupt_gz_raises(tmp_path):
    p = tmp_path / "auth.log.2.gz"
    p.write_bytes(b"not gzip at all")
    with pytest.raises(LogReadError, match="cannot read"):
        list(read_lines(p))

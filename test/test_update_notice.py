"""The update notice: once a day at most, only for a person, never in the way."""

from __future__ import annotations

import io
import json
import pathlib
import sys
import urllib.error
from typing import Any

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber import update_notice
from tmxcaliber.lib.remote.errors import RemoteError
from tmxcaliber.update_notice import (
    CHECK_INTERVAL,
    OPT_OUT,
    PYPI_URL,
    STATE_FILE,
    UpdateCheck,
    enabled,
    fetch_latest,
    notice,
    release,
)

NOW = 1_800_000_000.0


class Terminal(io.StringIO):
    """A stream a person is reading."""

    def isatty(self) -> bool:
        """Report a terminal.

        Returns:
            True.
        """
        return True


class Fetch:
    """A stand-in for PyPI that records each question."""

    def __init__(self, answer: str | None) -> None:
        self.answer = answer
        self.calls = 0

    def __call__(self) -> str | None:
        """Answer as configured.

        Returns:
            The configured answer.
        """
        self.calls += 1
        return self.answer


def _check(
    tmp_path: pathlib.Path,
    fetch: Fetch,
    *,
    now: float = NOW,
    stream: io.StringIO | None = None,
    **env: str,
) -> UpdateCheck:
    return UpdateCheck(
        env={"TMXCALIBER_CACHE_DIR": str(tmp_path), **env},
        stream=Terminal() if stream is None else stream,
        fetch=fetch,
        clock=lambda: now,
        current="0.13.0",
    )


def _state(tmp_path: pathlib.Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((tmp_path / STATE_FILE).read_text("utf-8"))
    return loaded


def test_only_a_final_release_is_read() -> None:
    assert release("0.13.0") == (0, 13, 0)
    assert release(" 1.2.3 ") == (1, 2, 3)
    assert release("1.0.0rc1") is None
    assert release("1.0") is None
    assert release(None) is None


@pytest.mark.parametrize(
    ("current", "latest", "says"),
    [
        ("0.13.0", "0.13.1", True),
        ("0.13.0", "1.0.0", True),
        ("0.13.0", "0.13.0", False),
        ("0.13.0", "0.12.9", False),
        ("0.13.0", None, False),
        ("0.13.0.dev1", "0.14.0", False),
    ],
)
def test_the_notice_names_only_a_newer_release(
    current: str, latest: str | None, says: bool
) -> None:
    message = notice(current, latest)

    assert (message is not None) is says
    if message:
        assert f"{current} -> {latest}" in message
        assert "pip install --upgrade tmxcaliber" in message


@pytest.mark.parametrize(
    ("env", "stream", "on"),
    [
        ({}, Terminal(), True),
        ({OPT_OUT: "1"}, Terminal(), False),
        ({"CI": "true"}, Terminal(), False),
        ({}, io.StringIO(), False),
    ],
    ids=["terminal", "opted out", "ci", "not a terminal"],
)
def test_it_runs_only_where_a_person_reads_it(
    env: dict[str, str], stream: io.StringIO, on: bool
) -> None:
    assert enabled(env, stream) is on


def test_a_fresh_answer_is_used_without_asking_again(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    (tmp_path / STATE_FILE).write_text(
        json.dumps({"checked_at": NOW - 60, "latest": "0.14.0"}), "utf-8"
    )
    fetch = Fetch("9.9.9")
    check = _check(tmp_path, fetch)

    # Act
    check.start()
    check.finish()

    # Assert
    assert fetch.calls == 0
    assert "0.13.0 -> 0.14.0" in capsys.readouterr().err


def test_a_due_check_asks_pypi_and_records_the_answer(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / STATE_FILE).write_text(
        json.dumps({"checked_at": NOW - CHECK_INTERVAL - 1, "latest": "0.13.0"}),
        "utf-8",
    )
    fetch = Fetch("0.14.0")
    check = _check(tmp_path, fetch)

    check.start()
    check.finish()

    assert fetch.calls == 1
    assert _state(tmp_path) == {"checked_at": NOW, "latest": "0.14.0"}
    assert "0.13.0 -> 0.14.0" in capsys.readouterr().err


def test_an_offline_check_says_nothing_and_waits_a_day(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    offline = Fetch(None)

    # Act
    first = _check(tmp_path, offline)
    first.start()
    first.finish()
    later = _check(tmp_path, offline, now=NOW + 60)
    later.start()
    later.finish()

    # Assert
    assert offline.calls == 1
    assert _state(tmp_path) == {"checked_at": NOW, "latest": None}
    assert capsys.readouterr().err == ""


def test_an_unreadable_cache_is_an_empty_answer(tmp_path: pathlib.Path) -> None:
    (tmp_path / STATE_FILE).write_text("not json", "utf-8")
    fetch = Fetch("0.13.0")
    check = _check(tmp_path, fetch)

    check.start()
    check.finish()

    assert fetch.calls == 1


def test_nothing_happens_where_no_person_reads_it(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fetch = Fetch("9.9.9")
    check = _check(tmp_path, fetch, stream=io.StringIO())

    check.start()
    check.finish()

    assert fetch.calls == 0
    assert not (tmp_path / STATE_FILE).exists()
    assert capsys.readouterr().err == ""


class _Answer(io.BytesIO):
    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.mark.parametrize(
    ("answer", "latest"),
    [
        (_Answer(json.dumps({"info": {"version": "0.14.0"}}).encode()), "0.14.0"),
        (_Answer(json.dumps({"info": {"version": "0.14.0rc1"}}).encode()), None),
        (_Answer(b"not json"), None),
        (_Answer(json.dumps({"releases": {}}).encode()), None),
        (urllib.error.URLError("offline"), None),
        (TimeoutError("slow"), None),
    ],
    ids=["release", "pre-release", "not json", "no version", "offline", "timeout"],
)
def test_pypi_is_read_for_its_latest_release_and_any_failure_is_none(
    answer: Any, latest: str | None
) -> None:
    asked: list[Any] = []

    def opener(request: Any, timeout: float) -> Any:
        asked.append((request.full_url, timeout))
        if isinstance(answer, BaseException):
            raise answer
        return answer

    assert fetch_latest(opener) == latest
    assert asked == [(PYPI_URL, update_notice.TIMEOUT)]


class _Recorder:
    """Stands in for `UpdateCheck` and records whether the notice was offered."""

    finished = 0

    def start(self) -> None:
        """Do nothing."""

    def finish(self) -> None:
        """Record the call."""
        type(self).finished += 1


def test_the_command_offers_the_notice_after_success_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange
    _Recorder.finished = 0
    monkeypatch.setattr(update_notice, "UpdateCheck", _Recorder)
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "-v"])

    # Act: a successful command, then a failed one.
    with pytest.raises(SystemExit) as succeeded:
        cli_module.main()

    def fail() -> None:
        raise RemoteError("the API refused")

    monkeypatch.setattr(cli_module, "_run", fail)
    with pytest.raises(SystemExit) as failed:
        cli_module.main()

    # Assert
    assert succeeded.value.code == 0
    assert failed.value.code == 1
    assert _Recorder.finished == 1

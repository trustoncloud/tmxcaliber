"""How the command line styles its messages, judged on fake streams."""

from __future__ import annotations

import io
import sys

import pytest

from tmxcaliber import console
from tmxcaliber.console import ASCII, GLYPHS, Branch
from tmxcaliber.lib.remote.errors import NoPackMatched, NotFound

GREEN = "\x1b[32m"
RED = "\x1b[31m"
RESET = "\x1b[0m"


class Stream(io.StringIO):
    """A text stream that says whether it is a terminal, and its encoding."""

    def __init__(self, *, tty: bool, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        """The encoding the stream reports.

        Returns:
            The encoding it was made with.
        """
        return self._encoding

    def isatty(self) -> bool:
        """Say whether the stream is a terminal.

        Returns:
            What it was made with.
        """
        return self._tty


class TerminalBytes(io.BytesIO):
    """The bytes under a terminal, so a text wrapper over it reports a tty."""

    def isatty(self) -> bool:
        """Say that this is a terminal.

        Returns:
            True.
        """
        return True


def cp1252(*, tty: bool) -> io.TextIOWrapper:
    """Make a stream that encodes as a Windows pipe or console does by default.

    Its errors are strict, so a glyph cp1252 cannot carry raises as it would
    on the real stream.

    Args:
        tty: Whether it reports a terminal.

    Returns:
        The stream.
    """
    buffer = TerminalBytes() if tty else io.BytesIO()
    return io.TextIOWrapper(buffer, encoding="cp1252", newline="")


def written(stream: io.TextIOWrapper) -> str:
    """Read back what a wrapped stream was given.

    Args:
        stream: The stream.

    Returns:
        Its bytes, decoded as it encoded them.
    """
    stream.flush()
    buffer = stream.buffer
    assert isinstance(buffer, io.BytesIO)
    return buffer.getvalue().decode(stream.encoding)


@pytest.fixture(autouse=True)
def windows_fixes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record each call that would fix a Windows console, and make none.

    The real call can replace the standard streams on an older console, which
    would hide what a test wrote.

    Args:
        monkeypatch: Replaces the call.

    Returns:
        One entry per call.
    """
    calls: list[int] = []
    monkeypatch.setattr(console, "_windows_fixed", False)
    monkeypatch.setattr(
        console.colorama, "just_fix_windows_console", lambda: calls.append(1)
    )
    return calls


def on_stderr(
    monkeypatch: pytest.MonkeyPatch, stream: object, **env: str
) -> console.Console:
    """Put a stream in place of stderr, and style messages for it.

    Args:
        monkeypatch: Replaces stderr.
        stream: The stream.
        **env: The environment.

    Returns:
        The console.
    """
    monkeypatch.setattr(sys, "stderr", stream)
    return console.stderr(env=env)


def test_a_utf8_terminal_gets_glyphs_and_color(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = Stream(tty=True)

    on_stderr(monkeypatch, stream).status("ok", "green", "Wrote 2 files")

    assert stream.getvalue() == f"{GREEN}\u2714 Wrote 2 files{RESET}\n"


def test_a_stream_that_is_no_terminal_gets_no_escape_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A pipe or a file is read by something other than a person.
    stream = Stream(tty=False)
    err = on_stderr(monkeypatch, stream)

    err.status("ok", "green", "Wrote 2 files")
    err.failure("aws-s3: archive failed", ["[unavailable]"], "Did you mean aws-ec2?")

    assert "\x1b" not in stream.getvalue()
    assert stream.getvalue().startswith("\u2714 Wrote 2 files\n\u2716 aws-s3")


@pytest.mark.parametrize(("value", "colored"), [("1", False), ("", True)])
def test_no_color_turns_color_off_on_a_terminal(
    monkeypatch: pytest.MonkeyPatch, value: str, colored: bool
) -> None:
    # https://no-color.org: set and not empty means no color, and the words and
    # the glyph stay.
    stream = Stream(tty=True)

    on_stderr(monkeypatch, stream, NO_COLOR=value).status("fail", "red", "Nothing")

    assert ("\x1b" in stream.getvalue()) is colored
    assert "\u2716 Nothing" in stream.getvalue()


@pytest.mark.parametrize("tty", [True, False], ids=["terminal", "pipe"])
def test_a_cp1252_stream_gets_the_ascii_set_and_never_raises(
    monkeypatch: pytest.MonkeyPatch, tty: bool
) -> None:
    stream = cp1252(tty=tty)
    err = on_stderr(monkeypatch, stream, NO_COLOR="1")

    err.status("info", "yellow", "Preview only", "Add --out DIR")
    err.failure(
        "ec3: manifest failed: No such pack.", ["[not_found]"], "Did you mean aws-ec2?"
    )
    err.tree("out", [Branch("aws-s3", (Branch("a"), Branch("b")))])

    assert written(stream) == (
        "[i] Preview only\n"
        "  Add --out DIR\n"
        "[x] ec3: manifest failed: No such pack.\n"
        "    [not_found]\n"
        "    -> Did you mean aws-ec2?\n"
        "out\n"
        "\\- aws-s3\n"
        "   |- a\n"
        "   \\- b\n"
    )


def test_every_glyph_has_an_ascii_stand_in_of_its_width_in_a_tree() -> None:
    assert set(GLYPHS) == set(ASCII)
    for role in ("last", "branch", "pipe"):
        assert len(ASCII[role]) == len(GLYPHS[role])
    assert all(text.isascii() for text in ASCII.values())


def test_the_windows_console_is_fixed_once_before_the_first_colored_write(
    monkeypatch: pytest.MonkeyPatch, windows_fixes: list[int]
) -> None:
    on_stderr(monkeypatch, Stream(tty=False)).line("plain")
    assert windows_fixes == []

    on_stderr(monkeypatch, Stream(tty=True)).line("one", "red")
    on_stderr(monkeypatch, Stream(tty=True)).line("two", "red")

    assert windows_fixes == [1]


def test_a_tree_draws_each_level_under_the_one_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = Stream(tty=True)
    err = on_stderr(monkeypatch, stream, NO_COLOR="1")

    err.tree(
        "C:\\ccr-try",
        [
            Branch(
                "aws-s3  (release 2adfa6b)",
                (
                    Branch("S3.C20", (Branch("metadata.json"), Branch("a/b.rego"))),
                    Branch("S3.C21", (Branch("metadata.json"),)),
                ),
            ),
            Branch("gcp-bigquery", (Branch("Bigquery.C102", (Branch("m.json"),)),)),
        ],
    )

    assert stream.getvalue() == (
        "C:\\ccr-try\n"
        "\u251c\u2500 aws-s3  (release 2adfa6b)\n"
        "\u2502  \u251c\u2500 S3.C20\n"
        "\u2502  \u2502  \u251c\u2500 metadata.json\n"
        "\u2502  \u2502  \u2514\u2500 a/b.rego\n"
        "\u2502  \u2514\u2500 S3.C21\n"
        "\u2502     \u2514\u2500 metadata.json\n"
        "\u2514\u2500 gcp-bigquery\n"
        "   \u2514\u2500 Bigquery.C102\n"
        "      \u2514\u2500 m.json\n"
    )


def test_a_failure_is_a_red_line_and_plain_lines_under_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = Stream(tty=True)

    on_stderr(monkeypatch, stream).failure(
        "ec3: manifest failed: No such pack.",
        ["[not_found, HTTP 404]", "The pack is unknown."],
        "Did you mean aws-ec2?",
    )

    assert stream.getvalue() == (
        f"{RED}\u2716 ec3: manifest failed: No such pack.{RESET}\n"
        "    [not_found, HTTP 404]\n"
        "    The pack is unknown.\n"
        "    \u2192 Did you mean aws-ec2?\n"
    )


def test_an_api_error_ends_with_its_suggestion_on_a_line_of_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = Stream(tty=False)
    error = NotFound(
        "Not found.",
        code="not_found",
        request_id="r-1",
        did_you_mean="Did you mean aws-ec2?",
    )

    on_stderr(monkeypatch, stream).error(error)

    assert stream.getvalue() == (
        "\u2716 Not found. (request r-1)\n    \u2192 Did you mean aws-ec2?\n"
    )
    # The library's text stays one line, with the suggestion where it was.
    assert str(error) == "Not found. Did you mean aws-ec2? (request r-1)"


def test_an_api_error_without_a_suggestion_is_one_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = Stream(tty=False)

    on_stderr(monkeypatch, stream).error(NotFound("Not found.", request_id="r-1"))

    assert stream.getvalue() == "\u2716 Not found. (request r-1)\n"


def test_a_suggestion_after_a_message_without_a_stop_starts_a_sentence() -> None:
    error = NoPackMatched("Nothing matched", did_you_mean="Did you mean gcp?")

    assert str(error) == "Nothing matched. Did you mean gcp?"
    assert error.headline == "Nothing matched"

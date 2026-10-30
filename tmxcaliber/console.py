"""How the command line styles what it tells a person.

Color and glyphs help someone reading a terminal and get in the way anywhere
else. An escape code written into a file or a pipe is noise to whatever reads
it, and a glyph that the stream's encoding cannot carry raises
``UnicodeEncodeError`` on the way out. So each is decided per stream, when a
message is about to be written to it: color only on a terminal and only while
``NO_COLOR`` is unset or empty (https://no-color.org), and glyphs only when the
stream's encoding can carry every one of them, with an ASCII set otherwise.
Every message keeps its glyph or the ASCII stand-in, and its words, with color
off, so color never carries the meaning alone.

Only the command line uses this. The library (`Client`, and ``str()`` of the
errors it raises) keeps plain one-line text, which a caller prints or logs as
it likes.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, TextIO

import colorama
from colorama import Fore, Style

from .lib.remote.errors import RemoteError

#: The glyph each role is drawn with on a stream that can carry them all.
GLYPHS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ok": "✔",
        "fail": "✖",
        "arrow": "→",
    }
)

#: The same roles in ASCII, for a stream whose encoding cannot carry `GLYPHS`,
#: such as a pipe or a file on Windows, which Python writes as cp1252.
ASCII: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ok": "[ok]",
        "fail": "[x]",
        "arrow": "->",
    }
)

#: The escape code each color name stands for.
_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "red": Fore.RED,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
    }
)

#: How far a suggestion is set in under the failure it follows.
INDENT: Final[str] = "    "

#: Whether `colorama.just_fix_windows_console` has run in this process.
_windows_fixed = False


def plural(number: int, noun: str) -> str:
    """Count something in words.

    Args:
        number: How many.
        noun: What, in the singular, such as ``file``.

    Returns:
        The number with thousands separators and the noun, such as ``1 file``
        or ``92,345 bytes``.
    """
    return f"{number:,} {noun}{'' if number == 1 else 's'}"


def _fix_windows_console() -> None:
    """Let an older Windows console render escape codes, once per process.

    A current Windows console renders them natively, and colorama then
    changes nothing. An older one shows them as text unless colorama wraps the
    standard streams, which it does here, before the first styled write.
    """
    global _windows_fixed
    if not _windows_fixed:
        _windows_fixed = True
        colorama.just_fix_windows_console()


def _is_terminal(stream: TextIO) -> bool:
    """Decide whether a stream is a terminal a person is reading.

    Args:
        stream: The stream.

    Returns:
        What its ``isatty`` says, and False for a stream that has none or is
        closed.
    """
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _carries_glyphs(stream: TextIO) -> bool:
    """Decide whether a stream's encoding can carry every glyph.

    Args:
        stream: The stream.

    Returns:
        True when each of `GLYPHS` encodes in the stream's encoding, read as
        ASCII when the stream names none.
    """
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "".join(GLYPHS.values()).encode(encoding)
    except (UnicodeError, LookupError, TypeError):
        return False
    return True


@dataclass(frozen=True)
class Console:
    """A stream, and how messages are styled on it.

    Attributes:
        stream: Where the messages go.
        color: Whether escape codes are written to it.
        glyphs: The glyph for each role, from `GLYPHS` or `ASCII`.
    """

    stream: TextIO
    color: bool
    glyphs: Mapping[str, str]

    def glyph(self, role: str) -> str:
        """Name the glyph for a role on this stream.

        Args:
            role: One of the keys of `GLYPHS`.

        Returns:
            The glyph, or its ASCII stand-in.
        """
        return self.glyphs[role]

    def paint(self, text: str, color: str | None) -> str:
        """Wrap text in a color's escape codes when this stream shows color.

        Args:
            text: The text.
            color: One of ``red``, ``green`` and ``yellow``, or None.

        Returns:
            The text, colored or as it was.
        """
        if not self.color or color is None or not text:
            return text
        return f"{_CODES[color]}{text}{Style.RESET_ALL}"

    def line(self, text: str = "", color: str | None = None) -> None:
        """Write one line.

        Args:
            text: The line, without its newline.
            color: Its color, if any.
        """
        print(self.paint(text, color), file=self.stream)

    def status(self, role: str, color: str, text: str) -> None:
        """Write a status line, its glyph first.

        Args:
            role: The glyph's role, such as ``ok``.
            color: The color of the line.
            text: The status.
        """
        self.line(f"{self.glyph(role)} {text}", color)

    def failure(self, headline: str, did_you_mean: str = "") -> None:
        """Write a failure, then what was probably meant on a line of its own.

        Args:
            headline: What failed, in red after the failure glyph.
            did_you_mean: A ``Did you mean ...?`` sentence, set in under the
                headline after an arrow and left plain, or empty for none.
        """
        self.line(f"{self.glyph('fail')} {headline}", "red")
        if did_you_mean:
            self.line(f"{INDENT}{self.glyph('arrow')} {did_you_mean}")

    def error(self, exc: RemoteError) -> None:
        """Write an API failure as a block.

        Args:
            exc: The failure. Its ``did_you_mean`` sentence, when it has one,
                ends the block on a line of its own.
        """
        self.failure(exc.headline, did_you_mean=exc.did_you_mean)


def _console(current: Callable[[], TextIO], env: Mapping[str, str] | None) -> Console:
    """Describe how messages are styled on a standard stream right now.

    The stream is looked up when a message is about to be written, so a
    stream replaced since the last message, as a test or a caller can do, is
    the one written to.

    Args:
        current: Returns the stream.
        env: The environment to read ``NO_COLOR`` from, the real one when None.

    Returns:
        The stream and its styling.
    """
    environ = os.environ if env is None else env
    stream = current()
    color = _is_terminal(stream) and not environ.get("NO_COLOR", "")
    if color:
        # colorama can replace the standard streams with ones that turn codes
        # into console calls, so the stream is looked up again afterwards.
        _fix_windows_console()
        stream = current()
    return Console(
        stream=stream,
        color=color,
        glyphs=GLYPHS if _carries_glyphs(stream) else ASCII,
    )


def stdout(env: Mapping[str, str] | None = None) -> Console:
    """Style messages for standard output, as it is now.

    Args:
        env: The environment, the real one when None.

    Returns:
        The console.
    """
    return _console(lambda: sys.stdout, env)


def stderr(env: Mapping[str, str] | None = None) -> Console:
    """Style messages for standard error, as it is now.

    Args:
        env: The environment, the real one when None.

    Returns:
        The console.
    """
    return _console(lambda: sys.stderr, env)

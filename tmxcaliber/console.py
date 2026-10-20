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

Only the command line uses this. The library (`Client`, `FetchResult`,
``str(PackFailure)``) keeps plain one-line text, which a caller prints or logs
as it likes.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
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
        "info": "ⓘ",
        "arrow": "→",
        "last": "└─",
        "branch": "├─",
        "pipe": "│",
    }
)

#: The same roles in ASCII, for a stream whose encoding cannot carry `GLYPHS`,
#: such as a pipe or a file on Windows, which Python writes as cp1252. Each
#: tree part is as wide as the glyph it stands for, so a tree keeps its shape.
ASCII: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ok": "[ok]",
        "fail": "[x]",
        "info": "[i]",
        "arrow": "->",
        "last": "\\-",
        "branch": "|-",
        "pipe": "|",
    }
)

#: The escape code each color name stands for.
_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "red": Fore.RED,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "dim": Style.DIM,
    }
)

#: How far the lines that explain a status line are set in under it.
INDENT: Final[str] = "    "

#: Whether `colorama.just_fix_windows_console` has run in this process.
_windows_fixed = False


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
class Branch:
    """One line of a tree, and the lines under it.

    Attributes:
        label: What the line says.
        children: The lines under it, in the order they are drawn.
    """

    label: str
    children: tuple[Branch, ...] = field(default=())


@dataclass(frozen=True)
class Console:
    """A stream, and how messages are styled on it.

    Attributes:
        stream: Where the messages go.
        terminal: Whether a person is reading it directly.
        color: Whether escape codes are written to it.
        glyphs: The glyph for each role, from `GLYPHS` or `ASCII`.
    """

    stream: TextIO
    terminal: bool
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
            color: One of ``red``, ``green``, ``yellow`` and ``dim``, or None.

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

    def status(self, role: str, color: str, text: str, *more: str) -> None:
        """Write a status line, and lines that continue it, in one color.

        Args:
            role: The glyph's role, such as ``ok``.
            color: The color of every line.
            text: The status.
            *more: Lines that continue it, set in by two spaces.
        """
        self.line(f"{self.glyph(role)} {text}", color)
        for extra in more:
            self.line(f"  {extra}", color)

    def failure(
        self, headline: str, details: Sequence[str] = (), did_you_mean: str = ""
    ) -> None:
        """Write a failure as a block: what failed, then what to know about it.

        Args:
            headline: What failed, in red after the failure glyph.
            details: Lines that explain it, set in under it and left plain.
            did_you_mean: A ``Did you mean ...?`` sentence that ends the block
                after an arrow, or empty for none.
        """
        self.line(f"{self.glyph('fail')} {headline}", "red")
        for detail in details:
            self.line(f"{INDENT}{detail}")
        if did_you_mean:
            self.line(f"{INDENT}{self.glyph('arrow')} {did_you_mean}")

    def error(self, exc: RemoteError) -> None:
        """Write an API failure as a block.

        Args:
            exc: The failure. Its ``did_you_mean`` sentence, when it has one,
                ends the block on a line of its own.
        """
        self.failure(exc.headline, did_you_mean=exc.did_you_mean)

    def tree(self, root: str, branches: Sequence[Branch]) -> None:
        """Write a tree, with its root on the first line.

        Args:
            root: The first line.
            branches: The lines under it.
        """
        self.line(root)
        self._branches(branches, "")

    def _branches(self, branches: Sequence[Branch], prefix: str) -> None:
        """Write the branches of one level, each followed by its own.

        Args:
            branches: The branches.
            prefix: What every line of this level starts with.
        """
        for index, branch in enumerate(branches):
            last = index == len(branches) - 1
            self.line(
                f"{prefix}{self.glyph('last' if last else 'branch')} {branch.label}"
            )
            # A level under the last branch has no line left to continue, so
            # it is set in by blanks as wide as the branch glyph and its space.
            below = " " * 3 if last else f"{self.glyph('pipe')}  "
            self._branches(branch.children, prefix + below)


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
    terminal = _is_terminal(stream)
    color = terminal and not environ.get("NO_COLOR", "")
    if color:
        # colorama can replace the standard streams with ones that turn codes
        # into console calls, so the stream is looked up again afterwards.
        _fix_windows_console()
        stream = current()
    return Console(
        stream=stream,
        terminal=terminal,
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

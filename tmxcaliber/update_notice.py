"""Tell an interactive user, at most daily, that a newer tmxcaliber is on PyPI.

Modeled on pip's own notice, and held to three rules so it can never get in the
way of a command:

* **Never on the command's path.** The notice comes from the answer cached by an
  earlier run. A check that is due refreshes that answer in a background thread,
  and the command waits for it at most `EXIT_WAIT` at the end, so a slow or absent
  network costs a fraction of a second, once a day.
* **Never on a failure.** No network, a refused request, an unreadable answer or a
  cache that cannot be written each leave the notice out; none raises, and a failed
  check is not retried until the next day, so an offline machine does not wait on
  every command.
* **Only where a person reads it.** Silent when stderr is not a terminal, under CI,
  and when `OPT_OUT` is set. It goes to stderr, so a command's results on stdout
  are never touched.

Only the ``tmxcaliber`` command checks. The library never does: an import that
reached the network would surprise every program built on it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from importlib import metadata
from pathlib import Path
from typing import Any, Final, TextIO

from . import console
from .lib.remote.cache import cache_root

LOGGER = logging.getLogger(__name__)

#: The distribution checked, and the name `pip install --upgrade` takes.
PACKAGE: Final[str] = "tmxcaliber"

#: PyPI's JSON description of the package; ``info.version`` is its latest release.
PYPI_URL: Final[str] = f"https://pypi.org/pypi/{PACKAGE}/json"

#: How often PyPI is asked, at most.
CHECK_INTERVAL: Final[float] = 24 * 60 * 60

#: How long one request may take.
TIMEOUT: Final[float] = 2.0

#: How long a finished command waits for a check still in flight.
EXIT_WAIT: Final[float] = 0.5

#: Set to anything non-empty to turn the check off.
OPT_OUT: Final[str] = "TMXCALIBER_NO_UPDATE_CHECK"

#: The cached answer, beside the ThreatModel cache.
STATE_FILE: Final[str] = "update-check.json"

_RELEASE: Final[re.Pattern[str]] = re.compile(r"(\d+)\.(\d+)\.(\d+)")

Fetch = Callable[[], str | None]


def release(text: object) -> tuple[int, int, int] | None:
    """Read a final release number, ``X.Y.Z``.

    Args:
        text: The version as published.

    Returns:
        Its three numbers, or None for anything else, such as a pre-release,
        which is never announced.
    """
    if not isinstance(text, str):
        return None
    match = _RELEASE.fullmatch(text.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def notice(current: str, latest: str | None) -> str | None:
    """Word the notice, when there is something newer to say.

    Args:
        current: The installed version.
        latest: The latest release on PyPI, or None when unknown.

    Returns:
        The line to print, or None when nothing newer is known.
    """
    installed, newest = release(current), release(latest)
    if installed is None or newest is None or newest <= installed:
        return None
    return (
        f"A new release of {PACKAGE} is available: {current} -> {latest}. "
        f"To update, run: pip install --upgrade {PACKAGE}"
    )


def enabled(env: Mapping[str, str], stream: TextIO) -> bool:
    """Tell whether this run may check and print.

    Args:
        env: The environment.
        stream: Where the notice would be written.

    Returns:
        False when opted out, under CI, or when no person is reading ``stream``.
    """
    if env.get(OPT_OUT, "").strip() or env.get("CI", "").strip():
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def installed_version() -> str | None:
    """Read the installed version.

    Returns:
        It, or None when the package metadata is missing, as in a bare checkout.
    """
    try:
        return metadata.version(PACKAGE)
    except metadata.PackageNotFoundError:
        return None


def fetch_latest(
    opener: Callable[..., Any] = urllib.request.urlopen, timeout: float = TIMEOUT
) -> str | None:
    """Ask PyPI for the latest release.

    Args:
        opener: Opens the request; injected so a test needs no network.
        timeout: Seconds the request may take.

    Returns:
        The latest final release, or None when it cannot be learned.
    """
    request = urllib.request.Request(
        PYPI_URL,
        headers={"Accept": "application/json", "User-Agent": f"{PACKAGE}-update-check"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            body = json.loads(response.read())
        latest = body["info"]["version"]
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
        LOGGER.debug("The update check could not read PyPI: %s", exc)
        return None
    return latest if release(latest) else None


def read_state(path: Path) -> dict[str, Any]:
    """Read the cached answer.

    Args:
        path: The state file.

    Returns:
        Its contents, or an empty answer when it is missing or unreadable.
    """
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOGGER.debug("No usable update-check state at %s: %s", path, exc)
        return {}
    return state if isinstance(state, dict) else {}


def write_state(path: Path, state: Mapping[str, Any]) -> None:
    """Store the answer, written whole or not at all.

    Args:
        path: The state file.
        state: What to store.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(
            "w", dir=path.parent, delete=False, encoding="utf-8", suffix=".tmp"
        ) as handle:
            json.dump(dict(state), handle)
        os.replace(handle.name, path)
    except OSError as exc:
        LOGGER.debug("The update-check state could not be written to %s: %s", path, exc)


class UpdateCheck:
    """One command's check: the cached answer now, a refresh when one is due.

    Args:
        env: The environment, defaulting to the real one.
        stream: Where the notice goes, defaulting to stderr.
        fetch: Learns the latest release; PyPI by default.
        clock: The current time in seconds.
        current: The installed version, read from the package by default.
    """

    def __init__(
        self,
        env: Mapping[str, str] | None = None,
        stream: TextIO | None = None,
        fetch: Fetch = fetch_latest,
        clock: Callable[[], float] = time.time,
        current: str | None = None,
    ) -> None:
        self._env = os.environ if env is None else env
        self._stream = sys.stderr if stream is None else stream
        self._fetch = fetch
        self._clock = clock
        self._current = current
        self._latest: str | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Read the cached answer, and refresh it in the background when due."""
        if not enabled(self._env, self._stream):
            return
        self._current = self._current or installed_version()
        if self._current is None:
            return
        path = cache_root(self._env) / STATE_FILE
        state = read_state(path)
        cached = state.get("latest")
        self._latest = cached if isinstance(cached, str) else None
        checked_at = state.get("checked_at")
        now = self._clock()
        if isinstance(checked_at, (int, float)) and now - checked_at < CHECK_INTERVAL:
            return
        self._thread = threading.Thread(
            target=self._refresh, args=(path, now), name="update-check", daemon=True
        )
        self._thread.start()

    def _refresh(self, path: Path, now: float) -> None:
        """Ask PyPI, and record the time even when it does not answer.

        Args:
            path: The state file.
            now: When the check started.
        """
        latest = self._fetch() or self._latest
        write_state(path, {"checked_at": now, "latest": latest})
        self._latest = latest

    def finish(self) -> None:
        """Print the notice, if there is one, waiting briefly for a refresh."""
        if self._current is None:
            return
        if self._thread is not None:
            self._thread.join(EXIT_WAIT)
        message = notice(self._current, self._latest)
        if message is None:
            return
        try:
            console.stderr(self._env).line(message, "yellow")
        except OSError as exc:
            LOGGER.debug("The update notice could not be written: %s", exc)

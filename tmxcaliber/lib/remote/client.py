"""HTTP transport for the TrustOnCloud API.

Built on ``urllib`` from the standard library. ``requests`` would buy
connection pooling and a retry policy that a command making one to a few
dozen calls does not need, and it would add a transitive dependency tree to
a package that publishes to PyPI on every merge and is installed unpinned
into a Lambda image. The cost of doing without it is this module.

The opener is injected rather than patched, so a test supplies a fake
instead of reaching into module globals the way the SCF cache's tests have
to.
"""

from __future__ import annotations

import json
import platform
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Final

from .config import Settings
from .errors import (
    BY_CODE,
    BY_STATUS,
    ContractViolation,
    InvalidCursor,
    RateLimited,
    RemoteError,
    ServiceUnavailable,
)

#: How many times a retryable failure is attempted in total.
MAX_ATTEMPTS: Final[int] = 3

#: The longest this client will sleep because a server asked it to.
#:
#: **The server reports the window, not the time remaining.** A 429 from the
#: hourly bucket carries ``Retry-After: 3600``, so a client that obeyed it
#: literally would hang a terminal for an hour. Past this cap the call fails
#: with the server's own wait time on the exception, and the caller decides.
MAX_RETRY_AFTER: Final[float] = 60.0

#: A page with a cursor that never advances is a defect, not a long read.
MAX_PAGES: Final[int] = 1000


def _user_agent() -> str:
    """Build the User-Agent this client sends.

    Carries the package version and the interpreter, and nothing that
    identifies the caller: the credential already tells the server who is
    asking, so a key id here would only put a secret-adjacent value in a
    second place.

    Returns:
        The header value.
    """
    try:
        from importlib.metadata import version

        release = version("tmxcaliber")
    except Exception:
        release = "0.0.0"
    return (
        f"tmxcaliber/{release} "
        f"(python {sys.version_info.major}.{sys.version_info.minor}; "
        f"{platform.system()})"
    )


def _retry_after(headers: Mapping[str, str]) -> float | None:
    """Read a Retry-After header, in seconds.

    Args:
        headers: The response headers.

    Returns:
        The delay, or None when the header is absent or unparseable.
    """
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if not raw:
        return None
    try:
        return float(raw.strip())
    except ValueError:
        # The HTTP-date form. Parsed rather than ignored, because a proxy may
        # well use it where the application would not.
        from email.utils import parsedate_to_datetime

        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        return max(0.0, when.timestamp() - time.time())


def _raise_for(status: int, body: bytes, headers: Mapping[str, str]) -> None:
    """Translate a failed response into the matching exception.

    Args:
        status: The HTTP status.
        body: The raw response body.
        headers: The response headers.

    Raises:
        RemoteError: Always; the subclass depends on the error code.
    """
    code = ""
    message = ""
    request_id = headers.get("X-Request-Id") or headers.get("x-request-id")
    try:
        envelope = json.loads(body.decode("utf-8"))
        error = envelope.get("error") if isinstance(envelope, dict) else None
        if isinstance(error, dict):
            code = str(error.get("code", ""))
            message = str(error.get("message", ""))
            request_id = str(error.get("requestId") or request_id or "") or None
    except (ValueError, UnicodeDecodeError):
        # Not the API's envelope. A distribution in front of the origin can
        # answer with an HTML error page, and guessing at it would be worse
        # than reporting the status.
        pass

    cls = BY_CODE.get(code) or BY_STATUS.get(status, RemoteError)
    text = message or f"The API answered {status}."
    if cls is RateLimited:
        raise RateLimited(
            text,
            retry_after=_retry_after(headers),
            code=code or "rate_limited",
            request_id=request_id,
            status=status,
        )
    raise cls(text, code=code, request_id=request_id, status=status)


class TocClient:
    """A read-only client for the TrustOnCloud API.

    Every route is a GET, which is what makes retrying safe by construction.
    Nothing here may be reused for a write without revisiting that.

    Args:
        settings: The resolved credential and endpoint.
        opener: The URL opener, injected so a test needs no network.
        sleep: The delay function, injected so a test needs no wall clock.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        opener: urllib.request.OpenerDirector | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._settings = settings
        self._opener = opener or urllib.request.build_opener()
        self._sleep = sleep

    @property
    def base_url(self) -> str:
        """The API root this client calls.

        Returns:
            The base URL, without a trailing slash.
        """
        return self._settings.base_url

    def _request(self, path: str, params: Mapping[str, str]) -> dict[str, Any]:
        """Perform one GET and parse the answer.

        Args:
            path: The path, beginning with a slash.
            params: Query parameters, empty values omitted.

        Returns:
            The decoded JSON object.

        Raises:
            RemoteError: On any failure, including a body that is not JSON.
        """
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        url = f"{self._settings.base_url}{path}" + (f"?{query}" if query else "")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self._settings.credentials.api_key}",
                "Accept": "application/json",
                "User-Agent": _user_agent(),
            },
        )
        try:
            with self._opener.open(request, timeout=self._settings.timeout) as response:
                body = response.read()
                headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            # `from None` deliberately. The urllib exception holds the Request,
            # and the Request holds the Authorization header, so chaining it
            # would put the key in every traceback.
            _raise_for(exc.code, exc.read(), dict(exc.headers.items()))
            raise  # unreachable; _raise_for always raises
        except urllib.error.URLError as exc:
            raise ServiceUnavailable(
                f"Could not reach {self._settings.base_url}: {exc.reason}",
                code="unreachable",
            ) from None
        except TimeoutError:
            raise ServiceUnavailable(
                f"{self._settings.base_url} did not answer within "
                f"{self._settings.timeout:.0f}s.",
                code="timeout",
            ) from None

        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            # Never routed through the CLI's JSON repair pass: on a truncated
            # body that would turn a transport failure into a document that
            # looks fine and is silently wrong.
            raise ContractViolation(
                f"{path} answered with a body that is not JSON.",
                code="bad_body",
                request_id=headers.get("X-Request-Id"),
            ) from None
        if not isinstance(parsed, dict):
            raise ContractViolation(
                f"{path} answered with {type(parsed).__name__}, not an object.",
                code="bad_body",
                request_id=headers.get("X-Request-Id"),
            )
        return parsed

    def get(self, path: str, params: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Fetch one resource, retrying the failures worth retrying.

        Args:
            path: The path, beginning with a slash.
            params: Query parameters.

        Returns:
            The decoded JSON object.

        Raises:
            RemoteError: On a failure that is not worth retrying, or when the
                attempts are exhausted.
        """
        attempt = 0
        while True:
            attempt += 1
            try:
                return self._request(path, params or {})
            except (RateLimited, ServiceUnavailable) as exc:
                if attempt >= MAX_ATTEMPTS:
                    raise
                wait = getattr(exc, "retry_after", None)
                if wait is not None and wait > MAX_RETRY_AFTER:
                    # Reporting beats sleeping. The server named a window, not
                    # a remaining time, and the caller can act on the number.
                    raise
                if wait is None:
                    wait = min(MAX_RETRY_AFTER, 2 ** (attempt - 1))
                self._sleep(wait * (0.5 + random.random() / 2))

    def paginate(
        self, path: str, params: Mapping[str, str] | None = None, *, page_size: int = 0
    ) -> Iterator[dict[str, Any]]:
        """Walk a collection, yielding rows.

        The cursor never reaches the caller. It is bound server-side to the
        credential, the route and the filters, so it is meaningless outside
        one walk and a caller shown one would be tempted to keep it.

        Args:
            path: The path, beginning with a slash.
            params: Query parameters other than ``limit`` and ``cursor``.
            page_size: Rows per request, or 0 for the server's default.

        Yields:
            Each row, in the order the API returns it.

        Raises:
            ContractViolation: If a page is not an envelope, if a cursor
                repeats, or if the walk does not terminate.
            RemoteError: On any transport or server failure.
        """
        query = dict(params or {})
        if page_size:
            query["limit"] = str(page_size)
        seen: set[str] = set()
        pages = 0
        while True:
            pages += 1
            if pages > MAX_PAGES:
                raise ContractViolation(
                    f"{path} did not finish within {MAX_PAGES} pages.",
                    code="walk_too_long",
                )
            try:
                body = self.get(path, query)
            except InvalidCursor as exc:
                # A cursor is bound to the credential, so a key rotated
                # part-way through invalidates the walk. The caller never saw
                # a cursor, so the word would mean nothing to them.
                raise ContractViolation(
                    "The page expired part-way through reading "
                    f"{path}; run the command again.",
                    code="invalid_cursor",
                    request_id=exc.request_id,
                ) from None
            items = body.get("items")
            if not isinstance(items, list):
                raise ContractViolation(
                    f"{path} answered without an items list.", code="bad_page"
                )
            for row in items:
                if isinstance(row, dict):
                    yield row
            cursor = body.get("nextCursor")
            if not cursor:
                return
            cursor = str(cursor)
            if cursor in seen:
                raise ContractViolation(
                    f"{path} returned a cursor it had already served.",
                    code="cursor_repeated",
                )
            if not items:
                raise ContractViolation(
                    f"{path} returned an empty page with more to come.",
                    code="empty_page",
                )
            seen.add(cursor)
            query["cursor"] = cursor

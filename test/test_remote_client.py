"""The HTTP transport: errors, retries and cursor walks.

Every test drives a fake opener. The conftest guard means a test that
reached a real socket would fail rather than quietly go to the network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from tmxcaliber.lib.remote import errors
from tmxcaliber.lib.remote.client import MAX_ATTEMPTS, MAX_RETRY_AFTER, TocClient
from tmxcaliber.lib.remote.config import Credentials, Settings

KEY = "toc-tak1-" + "A" * 16 + "-" + "B" * 52


def settings(base_url: str = "https://api.example.test") -> Settings:
    """Build settings with a well-formed credential.

    Args:
        base_url: The API root.

    Returns:
        The settings.
    """
    return Settings(
        credentials=Credentials(api_key=KEY, source="test"),
        base_url=base_url,
        timeout=1.0,
    )


class FakeResponse:
    """The slice of an HTTP response the client reads."""

    def __init__(self, body: Any, headers: dict[str, str] | None = None) -> None:
        self._body = json.dumps(body).encode("utf-8")
        self.headers = headers or {}

    def read(self) -> bytes:
        """Return the body.

        Returns:
            The encoded body.
        """
        return self._body

    def __enter__(self) -> FakeResponse:
        """Enter the context manager.

        Returns:
            Self.
        """
        return self

    def __exit__(self, *exc: object) -> None:
        """Leave the context manager."""
        return None


class FakeOpener(urllib.request.OpenerDirector):
    """An opener that replays queued answers and records the requests."""

    def __init__(self, answers: list[Any]) -> None:
        super().__init__()
        self.answers = answers
        self.requests: list[urllib.request.Request] = []

    def open(self, fullurl: Any, data: Any = None, timeout: Any = None) -> Any:
        """Answer the next queued response, or raise it.

        Args:
            fullurl: The request.
            data: Unused.
            timeout: Unused.

        Returns:
            The next queued response.

        Raises:
            BaseException: When the queued answer is an exception.
        """
        self.requests.append(fullurl)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def http_error(
    status: int, body: Any, headers: dict[str, str] | None = None
) -> urllib.error.HTTPError:
    """Build an HTTPError carrying an API error envelope.

    Args:
        status: The HTTP status.
        body: The response body.
        headers: Response headers.

    Returns:
        The error.
    """
    import io

    return urllib.error.HTTPError(
        "https://api.example.test/v1/me",
        status,
        "error",
        headers or {},  # type: ignore[arg-type]
        io.BytesIO(json.dumps(body).encode("utf-8")),
    )


def test_the_credential_travels_in_the_authorization_header() -> None:
    opener = FakeOpener([FakeResponse({"tenantId": "t-1"})])
    client = TocClient(settings(), opener=opener)

    client.get("/v1/me")

    sent = opener.requests[0]
    assert sent.get_header("Authorization") == f"Bearer {KEY}"
    assert "toc-tak1" not in sent.full_url


def test_the_user_agent_names_no_caller() -> None:
    opener = FakeOpener([FakeResponse({})])
    TocClient(settings(), opener=opener).get("/v1/me")

    agent = opener.requests[0].get_header("User-agent") or ""
    assert agent.startswith("tmxcaliber/")
    assert KEY not in agent
    assert "toc-tak1" not in agent


@pytest.mark.parametrize(
    ("code", "status", "expected"),
    [
        ("invalid_credential", 401, errors.AuthenticationError),
        ("ip_not_allowed", 403, errors.AddressNotAllowed),
        ("forbidden", 403, errors.PermissionDenied),
        ("not_found", 404, errors.NotFound),
        ("invalid_request", 400, errors.InvalidRequest),
        ("invalid_cursor", 400, errors.InvalidCursor),
        ("unavailable", 503, errors.ServiceUnavailable),
    ],
)
def test_every_published_error_code_maps(
    code: str, status: int, expected: type[Exception]
) -> None:
    # `unavailable` is retried, so the fake must be able to answer every
    # attempt; the others are refused on the first.
    answers = [
        http_error(
            status,
            {"error": {"code": code, "message": "nope", "requestId": "r-1"}},
        )
        for _ in range(MAX_ATTEMPTS)
    ]
    opener = FakeOpener(answers)
    client = TocClient(settings(), opener=opener, sleep=lambda _: None)

    with pytest.raises(expected) as caught:
        client.get("/v1/me")
    assert "r-1" in str(caught.value)


def test_a_body_that_is_not_the_envelope_falls_back_to_the_status() -> None:
    # A distribution in front of the origin can answer with an HTML page.
    import io

    error = urllib.error.HTTPError(
        "https://api.example.test/v1/me",
        502,
        "bad gateway",
        {},  # type: ignore[arg-type]
        io.BytesIO(b"<html>nope</html>"),
    )
    opener = FakeOpener([error for _ in range(MAX_ATTEMPTS)])
    client = TocClient(settings(), opener=opener, sleep=lambda _: None)

    with pytest.raises(errors.ServiceUnavailable):
        client.get("/v1/me")
    # Retried to the limit, because a gateway failure is usually transient.
    assert len(opener.requests) == MAX_ATTEMPTS


def test_an_hour_long_retry_after_is_reported_rather_than_slept() -> None:
    # The server sends the window, not the time remaining, so obeying it
    # literally would hang the terminal for an hour.
    slept: list[float] = []
    opener = FakeOpener(
        [
            http_error(
                429,
                {"error": {"code": "rate_limited", "message": "slow down"}},
                {"Retry-After": "3600"},
            )
        ]
    )
    client = TocClient(settings(), opener=opener, sleep=slept.append)

    with pytest.raises(errors.RateLimited) as caught:
        client.get("/v1/me")
    assert caught.value.retry_after == 3600
    assert slept == []


def test_a_short_retry_after_is_honoured_and_the_call_succeeds() -> None:
    slept: list[float] = []
    opener = FakeOpener(
        [
            http_error(
                429,
                {"error": {"code": "rate_limited", "message": "slow down"}},
                {"Retry-After": "2"},
            ),
            FakeResponse({"tenantId": "t-1"}),
        ]
    )
    client = TocClient(settings(), opener=opener, sleep=slept.append)

    assert client.get("/v1/me") == {"tenantId": "t-1"}
    assert len(slept) == 1
    assert 0 < slept[0] <= MAX_RETRY_AFTER


def test_a_refused_credential_is_never_retried() -> None:
    opener = FakeOpener(
        [http_error(401, {"error": {"code": "invalid_credential", "message": "no"}})]
    )
    client = TocClient(settings(), opener=opener, sleep=lambda _: None)

    with pytest.raises(errors.AuthenticationError):
        client.get("/v1/me")
    assert len(opener.requests) == 1


def test_a_walk_follows_cursors_and_stops() -> None:
    opener = FakeOpener(
        [
            FakeResponse({"items": [{"a": 1}], "nextCursor": "c1", "pageSize": 1}),
            FakeResponse({"items": [{"a": 2}], "nextCursor": None, "pageSize": 1}),
        ]
    )
    client = TocClient(settings(), opener=opener)

    assert list(client.paginate("/v1/threatmodels")) == [{"a": 1}, {"a": 2}]


def test_a_repeated_cursor_is_a_contract_violation() -> None:
    # Otherwise the walk never ends, and it spends the caller's hourly budget
    # doing it.
    opener = FakeOpener(
        [
            FakeResponse({"items": [{"a": 1}], "nextCursor": "same", "pageSize": 1}),
            FakeResponse({"items": [{"a": 2}], "nextCursor": "same", "pageSize": 1}),
        ]
    )
    client = TocClient(settings(), opener=opener)

    with pytest.raises(errors.ContractViolation):
        list(client.paginate("/v1/threatmodels"))


def test_an_empty_page_promising_more_is_a_contract_violation() -> None:
    opener = FakeOpener(
        [FakeResponse({"items": [], "nextCursor": "c1", "pageSize": 0})]
    )
    client = TocClient(settings(), opener=opener)

    with pytest.raises(errors.ContractViolation):
        list(client.paginate("/v1/threatmodels"))


def test_a_page_without_an_items_list_is_a_contract_violation() -> None:
    client = TocClient(settings(), opener=FakeOpener([FakeResponse({"rows": []})]))

    with pytest.raises(errors.ContractViolation):
        list(client.paginate("/v1/threatmodels"))


def test_an_expired_cursor_mid_walk_says_to_rerun() -> None:
    # Cursors are bound to the credential, so a rotation part-way through
    # invalidates the walk. The caller never saw a cursor.
    opener = FakeOpener(
        [
            FakeResponse({"items": [{"a": 1}], "nextCursor": "c1", "pageSize": 1}),
            http_error(400, {"error": {"code": "invalid_cursor", "message": "stale"}}),
        ]
    )
    client = TocClient(settings(), opener=opener, sleep=lambda _: None)

    with pytest.raises(errors.ContractViolation) as caught:
        list(client.paginate("/v1/threatmodels"))
    assert "again" in str(caught.value)


def test_a_body_that_is_not_json_is_a_contract_violation() -> None:
    class Garbage(FakeResponse):
        def read(self) -> bytes:
            return b"<html>"

    client = TocClient(settings(), opener=FakeOpener([Garbage({})]))

    with pytest.raises(errors.ContractViolation):
        client.get("/v1/me")


def test_empty_parameters_are_not_sent() -> None:
    opener = FakeOpener([FakeResponse({"items": [], "nextCursor": None})])
    client = TocClient(settings(), opener=opener)

    client.get("/v1/threatmodels", {"provider": "", "release": "r1"})

    assert "release=r1" in opener.requests[0].full_url
    assert "provider" not in opener.requests[0].full_url

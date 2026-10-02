"""Shared test setup.

The one thing here is a guard: no test may open a socket.

The package gained an HTTP client, and a client's tests are exactly the
place where a fixture quietly stops being a fixture. A test that reached the
real API would be slow, would need a credential, would spend the caller's
hourly budget, and would pass or fail for reasons that have nothing to do
with the code under test. There was no guard before because there was
nothing to guard.

A test that genuinely needs a socket marks itself ``@pytest.mark.network``.
Nothing does today.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any, NoReturn

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register the marker that opts a test out of the guard.

    Args:
        config: The pytest configuration.
    """
    config.addinivalue_line(
        "markers", "network: the test genuinely needs a real socket"
    )


@pytest.fixture(autouse=True)
def no_network(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Fail any test that tries to open a socket.

    Args:
        request: The running test, so a marked one can opt out.
        monkeypatch: Used to replace the socket constructor.

    Yields:
        None, for the duration of the test.
    """
    if request.node.get_closest_marker("network"):
        yield
        return

    def refuse(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError(
            "this test opened a socket; mock the transport, or mark the test "
            "with @pytest.mark.network if it really needs one"
        )

    monkeypatch.setattr(socket, "socket", refuse)
    yield

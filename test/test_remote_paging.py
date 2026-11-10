"""Paging: the page size every collection is read at, and reading one page.

A walk reads a whole collection at the largest page its contract permits.
``--page`` and ``--cursor`` on the command line, and ``.page()`` on a paged
`Client` method, read exactly one page and hand back its ``nextCursor`` so
the caller decides how many calls to spend.
"""

from __future__ import annotations

import pathlib
import urllib.parse
from typing import Any

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber import remote_cli
from tmxcaliber.lib.remote.api import Client, Operation, PagedOperation
from tmxcaliber.lib.remote.client import TocClient
from tmxcaliber.lib.remote.contract import route_for
from tmxcaliber.lib.remote.errors import (
    ContractViolation,
    IncompleteAnswer,
    InvalidCursor,
)

from .test_remote_api import page
from .test_remote_client import FakeOpener, FakeResponse, http_error, settings
from .test_remote_config import KEY

THREATMODELS = route_for(("threatmodels", "list"))
MAPPINGS = route_for(("compliance", "mappings", "list"))
UNRESOLVED = ["aws-s3"]


@pytest.fixture(autouse=True)
def isolated_credentials(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolve every client from a known environment, never the caller's own.

    Args:
        tmp_path: Where the absent credentials file would live.
        monkeypatch: Used to set the environment.
    """
    monkeypatch.delenv("TOC_API_URL", raising=False)
    monkeypatch.setenv("TOC_API_KEY", KEY)
    monkeypatch.setenv("TOC_CONFIG_FILE", str(tmp_path / "absent"))


def query_of(opener: FakeOpener, index: int = 0) -> dict[str, str]:
    """Read the query one request sent.

    Args:
        opener: The opener that recorded the request.
        index: Which request.

    Returns:
        The query, by name.
    """
    sent = urllib.parse.urlsplit(opener.requests[index].full_url)
    return dict(urllib.parse.parse_qsl(sent.query))


def run(argv: list[str], *answers: Any) -> tuple[Any, FakeOpener, list[str]]:
    """Parse a command line and run it against queued answers.

    Args:
        argv: The arguments after the program name.
        *answers: What the API answers, in order.

    Returns:
        The result, the opener, and what the API reported incomplete.
    """
    opener = FakeOpener(list(answers))
    incomplete: list[str] = []
    result, _ = remote_cli.run_api_command(
        cli_module.get_params(argv),
        client=TocClient(settings(), opener=opener),
        incomplete=incomplete,
    )
    return result, opener, incomplete


def test_a_walk_asks_for_the_largest_page_the_route_permits() -> None:
    assert THREATMODELS is not None and THREATMODELS.page_maximum is not None

    rows, opener, _ = run(
        ["threatmodels", "list"], FakeResponse(page(THREATMODELS, []))
    )

    assert rows == []
    assert query_of(opener)["limit"] == str(THREATMODELS.page_maximum)


def test_a_limit_given_is_the_page_size_sent() -> None:
    assert THREATMODELS is not None

    _, opener, _ = run(
        ["threatmodels", "list", "--limit", "10"], FakeResponse(page(THREATMODELS, []))
    )

    assert query_of(opener)["limit"] == "10"


def test_page_reads_one_page_and_hands_back_its_cursor() -> None:
    # Arrange: a page promising more, which a walk would follow.
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "aws-s3"}], cursor="c-2")

    # Act
    result, opener, _ = run(["threatmodels", "list", "--page"], FakeResponse(served))

    # Assert
    assert result == served
    assert result["nextCursor"] == "c-2"
    assert len(opener.requests) == 1
    assert "cursor" not in query_of(opener)


def test_a_cursor_reads_the_page_after_it_and_implies_page() -> None:
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "gcp-gke"}])

    result, opener, _ = run(
        ["threatmodels", "list", "--provider", "gcp", "--cursor", "c-2"],
        FakeResponse(served),
    )

    assert result["nextCursor"] is None
    assert query_of(opener) == {
        "provider": "gcp",
        "cursor": "c-2",
        "limit": str(THREATMODELS.page_maximum),
    }


def test_a_cursor_the_api_refuses_is_reported_as_the_apis_refusal() -> None:
    # A walk never shows its cursor, so it rewords this; a caller who passed
    # one needs the API's own answer, such as a cursor read with other filters.
    refusal = http_error(
        400, {"error": {"code": "invalid_cursor", "message": "Not valid here."}}
    )

    with pytest.raises(InvalidCursor):
        run(["threatmodels", "list", "--cursor", "stale"], refusal)


def test_an_incomplete_page_is_reported_as_an_incomplete_walk_is() -> None:
    assert MAPPINGS is not None
    served = {**page(MAPPINGS, []), "unresolvedTmIds": UNRESOLVED}

    result, _, incomplete = run(
        ["compliance", "mappings", "list", "--framework-id", "f", "--page"],
        FakeResponse(served),
    )

    assert result["unresolvedTmIds"] == UNRESOLVED
    assert incomplete == ['unresolvedTmIds: ["aws-s3"]']


def test_a_route_that_is_not_paged_takes_no_page_option() -> None:
    with pytest.raises(SystemExit) as caught:
        cli_module.get_params(["me", "--page"])

    assert caught.value.code == 2


@pytest.mark.parametrize(
    "served",
    [
        {"items": [], "pageSize": 5},
        {"items": [], "nextCursor": "more", "pageSize": 5},
        {"items": ["not an object"], "nextCursor": None, "pageSize": 5},
    ],
    ids=["no cursor", "empty page promising more", "row not an object"],
)
def test_one_page_is_held_to_every_check_a_walk_applies(served: dict[str, Any]) -> None:
    client = TocClient(settings(), opener=FakeOpener([FakeResponse(served)]))

    with pytest.raises(ContractViolation):
        client.page("/v1/threatmodels")


def test_a_paged_client_method_reads_one_page() -> None:
    # Arrange
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "aws-s3"}], cursor="c-2")
    opener = FakeOpener([FakeResponse(served)])
    client: Any = Client(opener=opener)

    # Act
    result = client.threatmodels.list.page(provider="aws", cursor="c-1")

    # Assert
    assert result == served
    assert query_of(opener) == {
        "provider": "aws",
        "cursor": "c-1",
        "limit": str(THREATMODELS.page_maximum),
    }


def test_only_a_paged_route_has_a_page_method() -> None:
    client: Any = Client(opener=FakeOpener([]))

    assert isinstance(client.threatmodels.list, PagedOperation)
    assert isinstance(client.me, Operation)
    assert not hasattr(client.me, "page")


def test_an_incomplete_page_raises_unless_accepted() -> None:
    assert MAPPINGS is not None
    served = {**page(MAPPINGS, []), "unresolvedTmIds": UNRESOLVED}
    client: Any = Client(
        opener=FakeOpener([FakeResponse(served), FakeResponse(served)])
    )

    with pytest.raises(IncompleteAnswer):
        client.compliance.mappings.list.page(framework_id="f")
    accepted = client.compliance.mappings.list.page(
        framework_id="f", allow_incomplete=True
    )

    assert accepted["unresolvedTmIds"] == UNRESOLVED

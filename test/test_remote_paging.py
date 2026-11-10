"""Paging: a collection a caller asks for is read one page at a time.

Every list command and every paged `Client` method reads exactly one page and
hands back its ``nextCursor``, so the caller decides how many calls to spend.
``limit`` is the rows in that page, the API's own default when omitted, and
``cursor`` continues from a previous page. Only this client's own reads that
need the whole answer walk a collection, at the largest page the contract
permits.
"""

from __future__ import annotations

import pathlib
import urllib.parse
from typing import Any

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber import remote_cli
from tmxcaliber.lib.remote.api import Client
from tmxcaliber.lib.remote.client import TocClient
from tmxcaliber.lib.remote.contract import route_for
from tmxcaliber.lib.remote.errors import (
    ContractViolation,
    IncompleteAnswer,
    InvalidCursor,
)
from tmxcaliber.lib.remote.operations import call_route

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


def test_a_list_command_reads_one_page_and_writes_it_whole() -> None:
    # Arrange: a page promising more, which nothing follows.
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "aws-s3"}], cursor="c-2")

    # Act
    result, opener, _ = run(["threatmodels", "list"], FakeResponse(served))

    # Assert: the API's own default page, one call, the cursor handed back.
    assert result == served
    assert result["nextCursor"] == "c-2"
    assert len(opener.requests) == 1
    assert query_of(opener) == {}


def test_a_limit_is_the_rows_asked_for_and_spends_one_call() -> None:
    # The defect this replaced: --limit 3 sized the requests of a walk, so one
    # OverWatch list spent a key's hourly budget three rows at a time.
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "aws-s3"}], cursor="c-2")

    result, opener, _ = run(
        ["threatmodels", "list", "--limit", "3"], FakeResponse(served)
    )

    assert result == served
    assert len(opener.requests) == 1
    assert query_of(opener)["limit"] == "3"


def test_a_cursor_reads_the_page_after_it() -> None:
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "gcp-gke"}])

    result, opener, _ = run(
        ["threatmodels", "list", "--provider", "gcp", "--cursor", "c-2"],
        FakeResponse(served),
    )

    assert result["nextCursor"] is None
    assert query_of(opener) == {"provider": "gcp", "cursor": "c-2"}


def test_a_cursor_the_api_refuses_is_reported_as_the_apis_refusal() -> None:
    # A caller who passed a cursor needs the API's own answer, such as a
    # cursor read with other filters.
    refusal = http_error(
        400, {"error": {"code": "invalid_cursor", "message": "Not valid here."}}
    )

    with pytest.raises(InvalidCursor):
        run(["threatmodels", "list", "--cursor", "stale"], refusal)


def test_an_incomplete_page_is_reported() -> None:
    assert MAPPINGS is not None
    served = {**page(MAPPINGS, []), "unresolvedTmIds": UNRESOLVED}

    result, _, incomplete = run(
        ["compliance", "mappings", "list", "--framework-id", "f"],
        FakeResponse(served),
    )

    assert result["unresolvedTmIds"] == UNRESOLVED
    assert incomplete == ['unresolvedTmIds: ["aws-s3"]']


@pytest.mark.parametrize(
    "argv",
    [
        ["threatmodels", "list", "--page"],
        ["me", "--cursor", "c-2"],
        ["me", "--limit", "3"],
    ],
    ids=["no --page: one page is the only answer", "unpaged cursor", "unpaged limit"],
)
def test_options_a_route_does_not_take_are_refused(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli_module.get_params(argv)

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
    result = client.threatmodels.list(provider="aws", cursor="c-1")

    # Assert
    assert result == served
    assert len(opener.requests) == 1
    assert query_of(opener) == {"provider": "aws", "cursor": "c-1"}


def test_a_client_limit_is_the_rows_asked_for() -> None:
    assert THREATMODELS is not None
    served = page(THREATMODELS, [{"tmId": "aws-s3"}], cursor="c-2")
    opener = FakeOpener([FakeResponse(served)])
    client: Any = Client(opener=opener)

    client.threatmodels.list(limit=3)

    assert len(opener.requests) == 1
    assert query_of(opener) == {"limit": "3"}


def test_a_paged_client_method_has_no_page_method() -> None:
    # Calling the method is reading one page, so there is nothing to opt into.
    client: Any = Client(opener=FakeOpener([]))

    assert not hasattr(client.threatmodels.list, "page")


def test_an_incomplete_page_raises_unless_accepted() -> None:
    assert MAPPINGS is not None
    served = {**page(MAPPINGS, []), "unresolvedTmIds": UNRESOLVED}
    client: Any = Client(
        opener=FakeOpener([FakeResponse(served), FakeResponse(served)])
    )

    with pytest.raises(IncompleteAnswer):
        client.compliance.mappings.list(framework_id="f")
    accepted = client.compliance.mappings.list(framework_id="f", allow_incomplete=True)

    assert accepted["unresolvedTmIds"] == UNRESOLVED


def test_the_clients_own_full_read_walks_at_the_largest_page() -> None:
    # Discovery and a "Did you mean" read need every row, so they still walk.
    assert THREATMODELS is not None and THREATMODELS.page_maximum is not None
    opener = FakeOpener(
        [
            FakeResponse(page(THREATMODELS, [{"tmId": "aws-s3"}], cursor="c-2")),
            FakeResponse(page(THREATMODELS, [{"tmId": "gcp-gke"}])),
        ]
    )

    answer = call_route(TocClient(settings(), opener=opener), THREATMODELS, "", {})

    assert [row["tmId"] for row in answer.result] == ["aws-s3", "gcp-gke"]
    assert query_of(opener, 0)["limit"] == str(THREATMODELS.page_maximum)
    assert query_of(opener, 1)["cursor"] == "c-2"

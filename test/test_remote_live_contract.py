"""The live contract: the API's own definition, read for one credential.

The served definition is the vendored document with its marks, which is what
the API serves today, so these tests read the real OverWatch routes rather
than synthetic ones. Every transport is a fake: discovery first, then the
definition it points at.
"""

from __future__ import annotations

import copy
import pathlib
import re
import sys
from collections.abc import Callable
from typing import Any, NoReturn

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber import remote_cli
from tmxcaliber.lib.remote import api as api_module
from tmxcaliber.lib.remote import contract
from tmxcaliber.lib.remote.api import Client
from tmxcaliber.lib.remote.client import TocClient
from tmxcaliber.lib.remote.contract import UnsupportedOperation
from tmxcaliber.lib.remote.errors import (
    AddressNotAllowed,
    ContractViolation,
    NotFound,
    PermissionDenied,
    RemoteError,
)
from tmxcaliber.lib.remote.live_contract import load_live_contract

from .test_remote_client import FakeOpener, FakeResponse, http_error, settings
from .test_remote_config import KEY

BASE = "https://api.example.test"
DEFINITION_URL = f"{BASE}/v1/apis/openapi.json"
UPDATES = "/v1/overwatch/updates"
UPDATE = "/v1/overwatch/updates/{overwatchId}"
ARCHIVE = "/v1/ccr/packs/{tmId}/archive"


@pytest.fixture(autouse=True)
def isolated_credentials(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolve every client from a known environment, never the caller's own.

    Args:
        tmp_path: Where the absent credentials file would live.
        monkeypatch: Used to set the environment.
    """
    monkeypatch.setenv("TOC_API_URL", BASE)
    monkeypatch.setenv("TOC_API_KEY", KEY)
    monkeypatch.setenv("TOC_CONFIG_FILE", str(tmp_path / "absent"))


def item(
    path: str, *filters: str, allowed: bool = True, operation_id: str = ""
) -> dict[str, Any]:
    """Build one discovery operation, in the shape the API serves.

    Discovery spells a path template Express's way (``:overwatchId``) where
    the definition writes ``{overwatchId}``, and names the operation by the
    definition's own ``operationId``, so both are built that way here.

    Args:
        path: The operation's path template, as the definition spells it.
        *filters: The filters this credential's tenant may send.
        allowed: Whether this credential may call it.
        operation_id: Its id, when the vendored definition does not have the
            path; otherwise the definition's own.

    Returns:
        The operation.
    """
    return {
        "operationId": operation_id
        or contract.contract()["paths"][path]["get"]["operationId"],
        "method": "GET",
        "path": re.sub(r"\{([^{}]+)\}", r":\1", path),
        "summary": "An operation.",
        "permission": None,
        "allowed": allowed,
        "filters": list(filters),
        "page": None,
        "fields": None,
        "retiredFields": None,
    }


def definition(
    *operations: Any,
    name: str = "trustoncloud",
    version: str = "v1",
    url: Any = DEFINITION_URL,
) -> dict[str, Any]:
    """Build one discovery row.

    Args:
        *operations: Its operations.
        name: The API's name.
        version: The definition's version.
        url: Its ``definitionUrl``.

    Returns:
        The row.
    """
    return {
        "id": f"{name}:{version}",
        "name": name,
        "version": version,
        "title": "TrustOnCloud API",
        "description": "The API.",
        "definitionUrl": url,
        "documentationUrl": None,
        "preferred": True,
        "operations": list(operations),
    }


def page(*rows: dict[str, Any], cursor: str | None = None) -> FakeResponse:
    """Answer one page of discovery.

    Args:
        *rows: The rows.
        cursor: The next cursor, or None on the last page.

    Returns:
        The response.
    """
    return FakeResponse({"items": list(rows), "nextCursor": cursor, "pageSize": 50})


def served() -> dict[str, Any]:
    """Build the definition the API serves: the vendored one, marks included.

    Returns:
        A copy safe to change.
    """
    return copy.deepcopy(contract.contract())


def every_operation() -> list[dict[str, Any]]:
    """List every operation the served definition has, with every filter.

    Returns:
        What a tenant that has everything is told.
    """
    return [
        item(path, *(p["name"] for p in path_item["get"].get("parameters", [])))
        for path, path_item in contract.contract()["paths"].items()
    ]


def answering(*answers: Any) -> FakeOpener:
    """Build an opener that answers in order, a document as a JSON response.

    Args:
        *answers: Responses, errors, or documents to serve as JSON.

    Returns:
        The opener.
    """
    return FakeOpener(
        [
            FakeResponse(answer) if isinstance(answer, dict) else answer
            for answer in answers
        ]
    )


def live_client(*answers: Any) -> tuple[TocClient, FakeOpener]:
    """Build a transport that answers discovery and the definition.

    Args:
        *answers: The answers, in order, as `answering` takes them.

    Returns:
        The client and its opener.
    """
    opener = answering(*answers)
    return TocClient(settings(BASE), opener=opener), opener


def test_discovery_then_the_definition_bind_the_overwatch_commands() -> None:
    # Arrange
    client, opener = live_client(
        page(definition(item(UPDATES), item(UPDATE))), served()
    )

    # Act
    live = load_live_contract(client)

    # Assert
    assert [request.full_url for request in opener.requests] == [
        f"{BASE}/v1/apis?limit=50",
        DEFINITION_URL,
    ]
    assert live.live
    assert live.route_for(("overwatch", "updates", "list")) is not None
    assert live.route_for(("overwatch", "updates", "get")) is not None


def test_a_parameterized_route_binds_although_discovery_spells_its_path_apart() -> None:
    # Discovery serves `/v1/overwatch/updates/:overwatchId` for the
    # definition's `{overwatchId}`; matching on the path once left every
    # parameterized marked route, and the archive's marked filters, unbound.
    listed = item(UPDATE)
    archive = item(ARCHIVE, "kind", "release", "matcher")
    client, _ = live_client(page(definition(listed, archive)), served())

    live = load_live_contract(client)

    route = live.route_for_path(ARCHIVE)
    assert listed["path"] == "/v1/overwatch/updates/:overwatchId"
    assert live.route_for(("overwatch", "updates", "get")) is not None
    assert route is not None and "matcher" in route.filters
    assert contract.route_for(("overwatch", "updates", "list")) is None


def test_a_marked_route_discovery_does_not_list_stays_out() -> None:
    client, _ = live_client(page(definition(item("/v1/me"))), served())

    live = load_live_contract(client)

    assert live.route_for_path(UPDATES) is None
    assert live.route_for_path("/v1/me") is not None


@pytest.mark.parametrize(
    ("listed", "filters"),
    [
        pytest.param((), ("kind", "release"), id="none listed"),
        pytest.param(
            ("kind", "release", "matcher"),
            ("kind", "release", "matcher"),
            id="one listed",
        ),
    ],
)
def test_a_marked_filter_binds_only_when_discovery_lists_it(
    listed: tuple[str, ...], filters: tuple[str, ...]
) -> None:
    client, _ = live_client(page(definition(item(ARCHIVE, *listed))), served())

    archive = load_live_contract(client).route_for_path(ARCHIVE)

    assert archive is not None
    assert set(archive.filters) == set(filters)


def test_a_route_this_credential_may_not_call_is_still_bound() -> None:
    # From outside the tenant's IP ranges discovery allows only itself and
    # the definition, but still lists what the tenant has; the command then
    # fails with the API's own refusal, as an unmarked one would.
    client, _ = live_client(
        page(definition(item(UPDATES, allowed=False), item(UPDATE, allowed=False))),
        served(),
    )

    live = load_live_contract(client)

    assert live.route_for_path(UPDATES) is not None


def test_a_listed_operation_the_definition_does_not_have_is_ignored() -> None:
    later = item("/v1/not/yet/served", operation_id="notYetServed")
    client, _ = live_client(page(definition(item(UPDATES), later)), served())

    live = load_live_contract(client)

    assert live.route_for_path(UPDATES) is not None
    assert live.route_for_path("/v1/not/yet/served") is None


def test_discovery_is_read_across_pages() -> None:
    client, opener = live_client(
        page(definition(name="another"), cursor="next"),
        page(definition(item(UPDATES))),
        served(),
    )

    live = load_live_contract(client)

    assert live.route_for_path(UPDATES) is not None
    assert len(opener.requests) == 3


@pytest.mark.parametrize(
    "rows",
    [
        pytest.param([], id="no definition"),
        pytest.param([definition(), definition()], id="two definitions"),
        pytest.param([definition(version="v2")], id="another version"),
        pytest.param([{**definition(), "operations": None}], id="operations null"),
        pytest.param([definition("not an object")], id="item not an object"),
        pytest.param([definition({**item(UPDATES), "operationId": ""})], id="empty id"),
        pytest.param(
            [definition({**item(UPDATES), "operationId": 3})], id="id not text"
        ),
        pytest.param(
            [
                definition(
                    {k: v for k, v in item(UPDATES).items() if k != "operationId"}
                )
            ],
            id="no id",
        ),
        pytest.param(
            [definition({**item(UPDATES), "filters": "kind"})], id="filters not a list"
        ),
        pytest.param(
            [definition({**item(UPDATES), "filters": [1]})], id="filter not text"
        ),
        pytest.param(
            [definition({**item(UPDATES), "filters": [""]})], id="empty filter"
        ),
        pytest.param(
            [definition({k: v for k, v in item(UPDATES).items() if k != "filters"})],
            id="no filters",
        ),
    ],
)
def test_discovery_in_another_shape_is_refused(rows: list[dict[str, Any]]) -> None:
    client, opener = live_client(page(*rows))

    with pytest.raises(ContractViolation) as caught:
        load_live_contract(client)

    assert caught.value.code == "bad_discovery"
    assert len(opener.requests) == 1


@pytest.mark.parametrize(
    "url",
    [
        "https://elsewhere.example.test/v1/apis/openapi.json",
        "http://api.example.test/v1/apis/openapi.json",
        "https://api.example.test:8443/v1/apis/openapi.json",
    ],
)
def test_a_definition_on_another_origin_is_never_asked_for(url: str) -> None:
    client, opener = live_client(page(definition(item(UPDATES), url=url)))

    with pytest.raises(RemoteError) as caught:
        load_live_contract(client)

    assert caught.value.code == "cross_origin_definition"
    assert len(opener.requests) == 1


@pytest.mark.parametrize(
    "url",
    [None, "", "/v1/apis/openapi.json", f"{DEFINITION_URL}?format=json"],
    ids=["null", "empty", "relative", "query"],
)
def test_a_definition_url_this_client_cannot_use_is_refused(url: Any) -> None:
    client, opener = live_client(page(definition(item(UPDATES), url=url)))

    with pytest.raises(ContractViolation) as caught:
        load_live_contract(client)

    assert caught.value.code == "bad_discovery"
    assert len(opener.requests) == 1


@pytest.mark.parametrize(
    "document",
    [
        {"openapi": "2.0", "paths": {"/v1/me": {}}},
        {"paths": {"/v1/me": {}}},
        {"openapi": "3.1.0", "paths": {}},
        {"openapi": "3.1.0", "paths": {"/v1/me": 5}},
    ],
    ids=["swagger 2", "no version", "no paths", "malformed path item"],
)
def test_a_definition_in_another_shape_is_refused(document: dict[str, Any]) -> None:
    client, _ = live_client(page(definition(item(UPDATES))), document)

    with pytest.raises(ContractViolation) as caught:
        load_live_contract(client)

    assert caught.value.code == "bad_definition"


def test_a_definition_newer_than_this_release_names_the_path_and_the_remedy() -> None:
    document = served()
    document["paths"]["/v1/widgets"] = {"post": {"summary": "Make a widget."}}
    client, _ = live_client(page(definition(item(UPDATES))), document)

    with pytest.raises(ContractViolation) as caught:
        load_live_contract(client)

    message = str(caught.value)
    assert caught.value.code == "unsupported_operation"
    assert isinstance(caught.value.__cause__, UnsupportedOperation)
    assert "/v1/widgets" in message
    assert "--live" in message and "upgrade tmxcaliber" in message


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [(404, "not_found", NotFound), (403, "ip_not_allowed", AddressNotAllowed)],
)
def test_a_discovery_failure_is_the_apis_own(
    status: int, code: str, expected: type[RemoteError]
) -> None:
    client, _ = live_client(
        http_error(status, {"error": {"code": code, "message": "nope"}})
    )

    with pytest.raises(expected):
        load_live_contract(client)


def test_a_live_client_has_the_overwatch_methods_and_others_do_not() -> None:
    # Arrange
    before = Client(opener=FakeOpener([]))
    opener = answering(page(definition(item(UPDATES), item(UPDATE))), served(), page())

    # Act
    live: Any = Client(contract="live", opener=opener)
    after = Client(opener=FakeOpener([]))
    rows = live.overwatch.updates.list()

    # Assert
    assert rows == []
    assert opener.requests[-1].full_url == f"{BASE}{UPDATES}"
    assert not hasattr(before, "overwatch")
    assert not hasattr(after, "overwatch")
    assert contract.route_for_path(UPDATES) is None


@pytest.mark.parametrize(
    ("code", "expected"),
    [("forbidden", PermissionDenied), ("ip_not_allowed", AddressNotAllowed)],
)
def test_a_listed_route_this_key_may_not_call_answers_with_the_apis_refusal(
    code: str, expected: type[RemoteError]
) -> None:
    # Bound although discovery says `allowed: false`, as an unmarked route is
    # offered regardless of permission: the API's 403 names the reason, where
    # a missing command would only say `overwatch` does not exist.
    opener = answering(
        page(definition(item(UPDATES, allowed=False), item(UPDATE, allowed=False))),
        served(),
        http_error(
            403, {"error": {"code": code, "message": "Refused.", "requestId": "r-9"}}
        ),
    )
    live: Any = Client(contract="live", opener=opener)

    with pytest.raises(expected) as caught:
        live.overwatch.updates.list()

    assert "r-9" in str(caught.value)


def test_a_vendored_client_makes_no_request() -> None:
    opener = FakeOpener([])

    Client(opener=opener)

    assert opener.requests == []


def test_an_unknown_contract_is_refused_before_any_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TOC_API_KEY")

    with pytest.raises(ValueError, match="vendored, live"):
        Client(contract="bogus")  # type: ignore[arg-type]


def test_the_client_endpoint_is_the_origin_the_definition_must_share() -> None:
    opener = FakeOpener([page(definition(item(UPDATES)))])

    with pytest.raises(RemoteError) as caught:
        Client(api_url="https://other.example.test", contract="live", opener=opener)

    assert caught.value.code == "cross_origin_definition"


def test_a_live_route_that_would_hide_a_client_attribute_is_refused() -> None:
    document = served()
    document["paths"]["/v1/get"] = {
        "get": {
            "summary": "A route whose command would hide Client.get.",
            "responses": {
                "200": {"content": {"application/json": {"schema": {"type": "object"}}}}
            },
        }
    }
    opener = answering(page(definition(item(UPDATES))), document)

    with pytest.raises(ContractViolation, match="'get' is already taken"):
        Client(contract="live", opener=opener)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        pytest.param([], "vendored", id="nothing"),
        pytest.param(["me"], "vendored", id="no flag"),
        pytest.param(["overwatch", "updates", "list", "--live"], "live", id="leaf"),
        pytest.param(["--live", "overwatch", "updates", "list"], "live", id="root"),
        pytest.param(["overwatch", "--live", "updates", "list"], "live", id="group"),
        pytest.param(["--contract", "live", "me"], "live", id="spaced"),
        pytest.param(["--contract=live", "me"], "live", id="joined"),
        pytest.param(
            ["--contract", "live", "--contract", "vendored", "me"],
            "vendored",
            id="last wins",
        ),
        pytest.param(["--contract", "bogus", "me"], "vendored", id="unknown value"),
        pytest.param(["me", "--", "--live"], "vendored", id="after double dash"),
        pytest.param(["filter", "x.json", "--live"], "vendored", id="local command"),
        pytest.param(["--live", "init"], "vendored", id="init"),
        pytest.param(["--live", "-h"], "live", id="root help"),
    ],
)
def test_the_contract_is_read_from_argv_before_parsing(
    argv: list[str], expected: str
) -> None:
    assert remote_cli.requested_contract(argv, {"filter", "init"}) == expected


def test_both_contracts_at_once_is_refused() -> None:
    with pytest.raises(ValueError, match="different contracts"):
        remote_cli.requested_contract(["--live", "--contract", "vendored", "me"], ())


def _connect_live(*answers: Any) -> Callable[[], TocClient]:
    """Stand in for `connect`, answering discovery and the definition.

    Args:
        *answers: The answers, in order.

    Returns:
        The replacement.
    """
    client, _ = live_client(*answers)
    return lambda: client


def _never_called() -> NoReturn:
    """Stand in for `connect` where no request may be made.

    Raises:
        AssertionError: Always.
    """
    raise AssertionError("the live contract was read")


@pytest.mark.parametrize(
    "argv",
    [
        ["overwatch", "updates", "list", "--live"],
        ["--live", "overwatch", "updates", "list"],
        ["overwatch", "--live", "updates", "list"],
        ["--contract=live", "overwatch", "updates", "list"],
    ],
)
def test_the_overwatch_command_parses_under_the_live_contract(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    monkeypatch.setattr(
        remote_cli, "connect", _connect_live(page(definition(item(UPDATES))), served())
    )

    params = cli_module.get_params(argv)

    route = remote_cli.selected_route(params)
    assert route is not None and route.path == UPDATES
    assert remote_cli.selected_contract(params).live


def test_the_live_help_lists_the_overwatch_group(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        remote_cli, "connect", _connect_live(page(definition(item(UPDATES))), served())
    )

    with pytest.raises(SystemExit) as caught:
        cli_module.get_params(["--contract", "live", "overwatch", "--help"])

    assert caught.value.code == 0
    assert "updates" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [["me"], ["threatmodels", "list", "--provider", "aws"]],
)
def test_a_command_without_the_flag_never_reads_the_live_contract(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    monkeypatch.setattr(remote_cli, "connect", _never_called)

    params = cli_module.get_params(argv)

    assert not remote_cli.selected_contract(params).live


@pytest.mark.parametrize(
    "argv",
    [
        ["--live", "filter", "{source}"],
        ["filter", "{source}", "--live"],
        ["--contract", "vendored", "filter", "{source}"],
    ],
)
def test_the_flag_on_a_local_command_is_refused_without_a_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path, argv: list[str]
) -> None:
    source = tmp_path / "model.json"
    source.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(remote_cli, "connect", _never_called)

    with pytest.raises(SystemExit) as caught:
        cli_module.get_params([word.format(source=source) for word in argv])

    assert caught.value.code == 2


def test_an_abbreviated_flag_is_refused_rather_than_ignored(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(remote_cli, "connect", _never_called)

    with pytest.raises(SystemExit) as caught:
        cli_module.get_params(["me", "--liv"])

    assert caught.value.code == 2
    assert "spell them out in full" in capsys.readouterr().err


def test_every_api_command_offers_both_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        cli_module.get_params(["me", "-h"])

    rendered = " ".join(capsys.readouterr().out.split())
    assert "--contract {vendored,live}" in rendered
    assert "--live" in rendered


def test_a_live_definition_this_release_cannot_bind_exits_with_a_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    document = served()
    document["paths"]["/v1/widgets"] = {"post": {"summary": "Make a widget."}}
    monkeypatch.setattr(
        remote_cli, "connect", _connect_live(page(definition(item(UPDATES))), document)
    )
    monkeypatch.setattr(
        sys, "argv", ["tmxcaliber", "overwatch", "updates", "list", "--live"]
    )

    with pytest.raises(SystemExit) as caught:
        cli_module.main()

    err = capsys.readouterr().err
    assert caught.value.code == 1
    assert "/v1/widgets" in err and "upgrade tmxcaliber" in err
    assert "Traceback" not in err


def test_a_live_route_that_clashes_with_a_local_command_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = served()
    document["paths"]["/v1/filter"] = {
        "get": {
            "summary": "A route whose command a local command already answers to.",
            "responses": {
                "200": {"content": {"application/json": {"schema": {"type": "object"}}}}
            },
        }
    }
    monkeypatch.setattr(
        remote_cli, "connect", _connect_live(page(definition(item(UPDATES))), document)
    )

    with pytest.raises(ContractViolation) as caught:
        cli_module.get_params(["me", "--live"])

    assert caught.value.code == "unsupported_operation"
    assert "/v1/filter" in str(caught.value)


def test_every_marked_route_and_filter_binds_on_both_surfaces_once_unlocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The guard for a flagged tenant: everything marked in today's contract
    # must reach discovery's answer through the loader, and then bind without
    # a clash with a local command, the CLI's own names, or a client
    # attribute, before any tenant is the first to find out.
    client_for_load, _ = live_client(page(definition(*every_operation())), served())
    everything = load_live_contract(client_for_load)
    monkeypatch.setattr(cli_module, "load_contract", lambda name: everything)
    monkeypatch.setattr(api_module, "load_live_contract", lambda client: everything)

    params = cli_module.get_params(["overwatch", "updates", "list", "--live"])
    client: Any = Client(contract="live", opener=FakeOpener([]))

    assert remote_cli.selected_route(params) is not None
    for route in everything.routes:
        holder = client
        for word in route.command:
            holder = getattr(holder, word)
    assert len(everything.routes) == len(contract.contract()["paths"])
    for path, path_item in contract.contract()["paths"].items():
        bound = everything.route_for_path(path)
        assert bound is not None
        assert (
            set(bound.filters)
            == {
                parameter["name"]
                for parameter in path_item["get"].get("parameters", [])
                if parameter["in"] == "query"
            }
            - contract.PAGING_PARAMETERS
        )

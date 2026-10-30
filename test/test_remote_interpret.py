"""The OpenAPI interpreter: a contract in, the CLI and `Client` out.

Every test here builds its own small contract, so each behavior is shown on
an operation the vendored document does not have. That is the property the
interpreter exists for: a route the API adds reaches both surfaces with no
code edit.
"""

from __future__ import annotations

import inspect
import pathlib
import sys
import urllib.parse
from argparse import ArgumentParser
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber import remote_cli
from tmxcaliber.lib.remote import api as api_module
from tmxcaliber.lib.remote import contract, operations
from tmxcaliber.lib.remote.api import Client
from tmxcaliber.lib.remote.contract import UnsupportedOperation, command_for, interpret
from tmxcaliber.lib.remote.operations import request_for

from .test_remote_client import FakeOpener, FakeResponse
from .test_remote_config import KEY

LIMIT = {"in": "query", "name": "limit", "schema": {"type": "integer", "maximum": 50}}
CURSOR = {"in": "query", "name": "cursor", "schema": {"type": "string"}}

UseContract = Callable[[dict[str, Any]], None]


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


@pytest.fixture
def use_contract(monkeypatch: pytest.MonkeyPatch) -> Iterator[UseContract]:
    """Stand a synthetic document in for the vendored one.

    Args:
        monkeypatch: Replaces the contract loader.

    Yields:
        A function that installs a document.
    """

    def use(document: dict[str, Any]) -> None:
        monkeypatch.setattr(contract, "contract", lambda: document)
        contract.routes.cache_clear()

    yield use
    contract.routes.cache_clear()


def document(paths: dict[str, Any]) -> dict[str, Any]:
    """Wrap paths in the smallest contract the client reads.

    Args:
        paths: The ``paths`` object.

    Returns:
        A contract with the ``Page`` schema every paged route extends.
    """
    page = {
        "type": "object",
        "required": ["items", "nextCursor", "pageSize"],
        "properties": {
            "items": {"type": "array"},
            "nextCursor": {"type": ["string", "null"]},
            "pageSize": {"type": "integer"},
        },
    }
    return {
        "openapi": "3.1.0",
        "paths": paths,
        "components": {"schemas": {"Page": page}},
    }


def operation(
    *parameters: dict[str, Any],
    paged: bool = False,
    summary: str = "Widgets.",
    content_type: str = "application/json",
) -> dict[str, Any]:
    """Build one GET operation.

    Args:
        *parameters: Its parameters, before the paging ones.
        paged: Whether it answers with a page, which adds ``limit``/``cursor``.
        summary: Its summary.
        content_type: The media type of its 200 response.

    Returns:
        The operation object.
    """
    schema: dict[str, Any] = {"type": "object"}
    if paged:
        schema = {"allOf": [{"$ref": "#/components/schemas/Page"}, {"type": "object"}]}
    return {
        "summary": summary,
        "parameters": [*parameters, *((LIMIT, CURSOR) if paged else ())],
        "responses": {"200": {"content": {content_type: {"schema": schema}}}},
    }


def query(name: str, *, required: bool = False, **schema: Any) -> dict[str, Any]:
    """Build a query parameter.

    Args:
        name: Its name.
        required: Whether the operation requires it.
        **schema: Schema keywords; ``description`` goes on the parameter.

    Returns:
        The parameter object.
    """
    description = schema.pop("description", None)
    parameter: dict[str, Any] = {
        "in": "query",
        "name": name,
        "required": required,
        "schema": {"type": "string", **schema},
    }
    if description is not None:
        parameter["description"] = description
    return parameter


def path_parameter(name: str) -> dict[str, Any]:
    """Build a path parameter.

    Args:
        name: Its name.

    Returns:
        The parameter object.
    """
    return {"in": "path", "name": name, "required": True, "schema": {"type": "string"}}


def api_parser() -> tuple[ArgumentParser, Any]:
    """Build a parser carrying only the API commands.

    Returns:
        The parser and its top-level subparser action.
    """
    parser = ArgumentParser(prog="tmxcaliber")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    remote_cli.add_api_parsers(subparsers)
    return parser, subparsers


WIDGETS = {
    "/v1/widgets": {
        "get": operation(
            query("colour", description="Only widgets of this colour."),
            paged=True,
            summary="Widgets this credential may see.",
        )
    },
    "/v1/widgets/{widgetId}": {"get": operation(path_parameter("widgetId"))},
}


@pytest.mark.parametrize(
    ("path", "paged", "command"),
    [
        ("/v1/widgets", True, ("widgets", "list")),
        ("/v1/widgets/{widgetId}", False, ("widgets", "get")),
        ("/v1/widgets/{widgetId}/parts", True, ("widgets", "parts")),
        ("/v1/widgets/{provider}/{service}/parts", False, ("widgets", "parts")),
        ("/v1/me", False, ("me",)),
        ("/v1/widgets/schema.json", False, ("widgets", "schema")),
    ],
)
def test_the_naming_rule(path: str, paged: bool, command: tuple[str, ...]) -> None:
    assert command_for(path, paged=paged) == command


def test_a_new_operation_becomes_a_command(use_contract: UseContract) -> None:
    # Arrange
    use_contract(document(WIDGETS))
    parser, subparsers = api_parser()

    # Act
    params = parser.parse_args(["widgets", "list", "--colour", "red"])

    # Assert
    assert params.api_route.path == "/v1/widgets"
    assert params.colour == "red"
    group_help = subparsers.choices["widgets"].format_help()
    assert "Widgets this credential may see." in group_help


def test_a_new_operation_becomes_a_client_method(use_contract: UseContract) -> None:
    use_contract(document(WIDGETS))

    client = Client(opener=FakeOpener([]))

    listing: Any = client.widgets.list  # type: ignore[attr-defined]
    assert list(inspect.signature(listing).parameters) == ["colour", "limit"]
    assert listing.__doc__ == "Widgets this credential may see."


def test_both_surfaces_run_one_executor_and_send_one_request(
    use_contract: UseContract,
) -> None:
    # Arrange
    use_contract(document(WIDGETS))
    parser, _ = api_parser()
    cli_opener = FakeOpener([FakeResponse({})])
    api_opener = FakeOpener([FakeResponse({})])

    # Act
    params = parser.parse_args(["widgets", "get", "w-1"])
    remote_cli.run_api_command(params, client=Client(opener=cli_opener))
    Client(opener=api_opener).widgets.get("w-1")  # type: ignore[attr-defined]

    # Assert
    assert remote_cli.call_route is operations.call_route
    assert api_module.call_route is operations.call_route
    sent = [
        urllib.parse.urlsplit(opener.requests[0].full_url).path
        for opener in (cli_opener, api_opener)
    ]
    assert sent == ["/v1/widgets/w-1", "/v1/widgets/w-1"]


def test_required_typed_and_enumerated_options(use_contract: UseContract) -> None:
    # Arrange
    use_contract(
        document(
            {
                "/v1/widgets": {
                    "get": operation(
                        query("colour", required=True),
                        query("size", type="integer"),
                        query("shape", enum=["round", "square"]),
                        paged=True,
                    )
                }
            }
        )
    )
    parser, _ = api_parser()

    # Act
    params = parser.parse_args(
        ["widgets", "list", "--colour", "red", "--size", "3", "--shape", "round"]
    )
    signature = inspect.signature(Client(opener=FakeOpener([])).widgets.list)  # type: ignore[attr-defined]

    # Assert
    assert (params.colour, params.size, params.shape) == ("red", 3, "round")
    for argv in (
        ["widgets", "list"],
        ["widgets", "list", "--colour", "red", "--size", "big"],
        ["widgets", "list", "--colour", "red", "--shape", "oval"],
    ):
        with pytest.raises(SystemExit):
            parser.parse_args(argv)
    assert signature.parameters["colour"].default is inspect.Parameter.empty
    assert signature.parameters["size"].default is None


def test_an_integer_zero_reaches_the_wire(use_contract: UseContract) -> None:
    use_contract(
        document(
            {
                "/v1/widgets": {
                    "get": operation(query("size", type="integer"), paged=True)
                }
            }
        )
    )
    parser, _ = api_parser()
    opener = FakeOpener(
        [FakeResponse({"items": [], "nextCursor": None, "pageSize": 5})]
    )

    remote_cli.run_api_command(
        parser.parse_args(["widgets", "list", "--size", "0"]),
        client=Client(opener=opener),
    )

    sent = urllib.parse.urlsplit(opener.requests[0].full_url)
    assert dict(urllib.parse.parse_qsl(sent.query))["size"] == "0"


def test_a_paged_operation_walks_every_page(use_contract: UseContract) -> None:
    use_contract(document(WIDGETS))
    opener = FakeOpener(
        [
            FakeResponse({"items": [{"id": 1}], "nextCursor": "next", "pageSize": 1}),
            FakeResponse({"items": [{"id": 2}], "nextCursor": None, "pageSize": 1}),
        ]
    )

    rows = Client(opener=opener).widgets.list()  # type: ignore[attr-defined]

    assert rows == [{"id": 1}, {"id": 2}]


def test_a_threatmodel_reference_fills_provider_and_service(
    use_contract: UseContract,
) -> None:
    # Arrange
    use_contract(
        document(
            {
                "/v1/widgets/{provider}/{service}": {
                    "get": operation(
                        path_parameter("provider"),
                        path_parameter("service"),
                        query("release"),
                    )
                }
            }
        )
    )
    (route,) = contract.routes()

    # Act
    path, query_string = request_for(route, "aws-s3@1611187200", {"release": ""})

    # Assert
    assert route.positional == "tm_id"
    assert path == "/v1/widgets/aws/s3"
    assert query_string == {"release": "1611187200"}


def test_a_single_path_parameter_is_the_positional(use_contract: UseContract) -> None:
    use_contract(document(WIDGETS))
    route = contract.route_for(("widgets", "get"))
    assert route is not None

    path, _ = request_for(route, "w-1", {})

    assert route.positional == "widget_id"
    assert path == "/v1/widgets/w-1"


def test_a_positional_value_stays_one_path_segment(use_contract: UseContract) -> None:
    use_contract(document(WIDGETS))
    route = contract.route_for(("widgets", "get"))
    assert route is not None

    path, _ = request_for(route, "../admin?x=1", {})

    assert path == "/v1/widgets/..%2Fadmin%3Fx%3D1"


def test_a_reference_route_without_release_cannot_be_pinned(
    use_contract: UseContract,
) -> None:
    # Arrange
    use_contract(
        document(
            {
                "/v1/widgets/{provider}/{service}": {
                    "get": operation(
                        path_parameter("provider"), path_parameter("service")
                    )
                }
            }
        )
    )
    (route,) = contract.routes()
    _, subparsers = api_parser()
    leaf = subparsers.choices["widgets"]._subparsers._group_actions[0].choices["get"]

    # Act
    unpinned, query_string = request_for(route, "aws-s3", {})

    # Assert
    assert (unpinned, query_string) == ("/v1/widgets/aws/s3", {})
    with pytest.raises(ValueError, match="takes no release"):
        request_for(route, "aws-s3@1611187200", {})
    assert "@release" not in leaf.format_help()


@pytest.mark.parametrize("name", ["operation", "output", "apiRoute", "api_level_1"])
def test_an_option_that_would_overwrite_a_cli_argument_is_refused(
    use_contract: UseContract, name: str
) -> None:
    use_contract(document({"/v1/widgets": {"get": operation(query(name), paged=True)}}))

    with pytest.raises(ValueError, match="would overwrite the CLI's own arguments"):
        api_parser()


def test_a_positional_names_the_listing_that_reports_it(
    use_contract: UseContract,
) -> None:
    use_contract(document(WIDGETS))
    _, subparsers = api_parser()

    text = subparsers.choices["widgets"]._subparsers._group_actions[0].choices["get"]
    rendered = " ".join(text.format_help().split())

    assert "WIDGET_ID" in rendered
    assert "as `widgets list` reports it" in rendered


def test_the_contract_describes_an_option_and_percent_is_safe(
    use_contract: UseContract,
) -> None:
    use_contract(
        document(
            {
                "/v1/widgets": {
                    "get": operation(
                        query("colour", description="Matches 100% of the name."),
                        query("size"),
                        paged=True,
                    )
                }
            }
        )
    )
    parser, _ = api_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["widgets", "list", "-h"])
    route = contract.route_for(("widgets", "list"))
    assert route is not None
    leaf = ArgumentParser()
    remote_cli._leaf(leaf, route)
    rendered = " ".join(leaf.format_help().split())

    assert "Matches 100% of the name." in rendered
    assert "filter by size." in rendered


def test_references_and_path_level_parameters_are_read(
    use_contract: UseContract,
) -> None:
    contract_document = document(
        {
            "/v1/widgets/{widgetId}": {
                "parameters": [path_parameter("widgetId")],
                "get": operation({"$ref": "#/components/parameters/Colour"}),
            }
        }
    )
    contract_document["components"]["parameters"] = {"Colour": query("colour")}
    use_contract(contract_document)

    (route,) = contract.routes()

    assert route.positional == "widget_id"
    assert route.filters == ("colour",)


def test_an_unbound_path_is_skipped(use_contract: UseContract) -> None:
    (unbound,) = contract.UNBOUND
    use_contract(
        document(
            {
                unbound: {
                    "get": operation(
                        path_parameter("tmId"), content_type="application/zip"
                    )
                }
            }
        )
    )

    assert contract.routes() == ()


@pytest.mark.parametrize(
    ("paths", "match"),
    [
        pytest.param(
            {"/v1/widgets": {"post": operation()}}, "only a lone GET", id="write method"
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation(), "delete": operation()}},
            "only a lone GET",
            id="a second method",
        ),
        pytest.param(
            {"/v1/widgets": {"get": {**operation(), "requestBody": {}}}},
            "request body",
            id="request body",
        ),
        pytest.param(
            {
                "/v1/widgets": {
                    "get": operation({"in": "header", "name": "X-Colour", "schema": {}})
                }
            },
            "header parameter",
            id="header parameter",
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation(content_type="text/csv")}},
            "not JSON",
            id="non-JSON response",
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation(summary=" ")}},
            "no summary",
            id="no summary",
        ),
        pytest.param(
            {"/v1/widgets": {"get": {**operation(paged=True), "parameters": []}}},
            "could not walk",
            id="page without cursor",
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation(LIMIT)}},
            "could not tell when to stop",
            id="limit on an unpaged route",
        ),
        pytest.param(
            {"/v1/widgets/{widgetId}": {"get": operation()}},
            "template names",
            id="undeclared path parameter",
        ),
        pytest.param(
            {
                "/v1/widgets/{a}/{b}": {
                    "get": operation(path_parameter("a"), path_parameter("b"))
                }
            },
            "one positional cannot fill",
            id="two path parameters",
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation(query("big", type="boolean"))}},
            "only string, integer",
            id="boolean option",
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation({"$ref": "other.json#/Colour"})}},
            "only local references",
            id="remote reference",
        ),
        pytest.param({"/v2/widgets": {"get": operation()}}, "under /v1/", id="v2"),
        pytest.param(
            {"/v1/wid-gets": {"get": operation()}}, "command word", id="hyphen"
        ),
        pytest.param({"/v1/class": {"get": operation()}}, "command word", id="keyword"),
        pytest.param(
            {
                "/v1/widgets": {"get": operation(paged=True)},
                "/v1/widgets/list": {"get": operation()},
            },
            "both answer to `widgets list`",
            id="same command",
        ),
        pytest.param(
            {
                "/v1/widgets": {"get": operation()},
                "/v1/widgets/{widgetId}": {
                    "get": operation(path_parameter("widgetId"))
                },
            },
            "both a command",
            id="command and group",
        ),
        pytest.param(
            {
                "/v1/widgets/{widgetId}": {
                    "get": operation(path_parameter("widgetId"), query("widgetId"))
                }
            },
            "two arguments",
            id="option shadows the positional",
        ),
        pytest.param(
            {
                "/v1/widgets": {
                    "get": {
                        **operation(),
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {"schema": {"type": "array"}}
                                }
                            }
                        },
                    }
                }
            },
            "not a JSON object",
            id="array outside a page",
        ),
        pytest.param(
            {"/v1/widgets": {"get": operation(query("allowIncomplete"), paged=True)}},
            "the client adds itself",
            id="reserved keyword",
        ),
    ],
)
def test_an_unsupported_operation_is_refused_by_path(
    paths: dict[str, Any], match: str
) -> None:
    with pytest.raises(UnsupportedOperation, match=match):
        interpret(document(paths))


@pytest.mark.parametrize("word", ["list", "init"])
def test_an_api_word_a_local_command_uses_is_refused(
    use_contract: UseContract, monkeypatch: pytest.MonkeyPatch, word: str
) -> None:
    use_contract(document({f"/v1/{word}": {"get": operation()}}))
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "-h"])

    with pytest.raises(ValueError, match=f"/v1/{word}: the command word '{word}'"):
        cli_module.get_params()

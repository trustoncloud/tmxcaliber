"""The library `Client`: its shape is the CLI's, and its calls reach the API."""

from __future__ import annotations

import inspect
import pathlib
import urllib.parse
import warnings
from typing import Any

import pytest

import tmxcaliber
import tmxcaliber.lib.remote as remote_package
from tmxcaliber.lib.remote import api as api_module
from tmxcaliber.lib.remote import errors as errors_module
from tmxcaliber.lib.remote.api import Client, Group, Operation
from tmxcaliber.lib.remote.config import DEFAULT_BASE_URL
from tmxcaliber.lib.remote.contract import (
    REFERENCE_PARAMETERS,
    Route,
    python_name,
    required_page_fields,
    route_for,
    routes,
)
from tmxcaliber.lib.remote.errors import (
    ConfigurationError,
    ContractViolation,
    IncompleteAnswer,
)
from tmxcaliber.lib.remote.operations import incompleteness_fields, request_for

from .test_remote_client import (
    ZIP,
    FakeBytesResponse,
    FakeOpener,
    FakeResponse,
    StrictOpener,
    http_error,
)
from .test_remote_config import HAZARD, KEY, OTHER, STORED_URL, write_config

#: A value for each kind of positional the contract's routes use.
POSITIONAL_VALUES = {"tm_id": "aws-s3"}


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


def page(route: Route, items: list[Any], cursor: str | None = None) -> dict[str, Any]:
    """Build a page the client accepts for a route.

    Every field the contract requires on the route's pages is present, with
    an empty value of its type, so the test does not restate the contract.

    Args:
        route: The route the page answers.
        items: The rows.
        cursor: The next cursor, or None on the last page.

    Returns:
        The page envelope.
    """
    body: dict[str, Any] = {"items": items, "nextCursor": cursor, "pageSize": 5}
    for name, types in required_page_fields(route.path).items():
        body.setdefault(name, types[0]())
    return body


def operation_for(client: Client, route: Route) -> Any:
    """Follow a route's command words down the client's attributes.

    Args:
        client: The client.
        route: The route.

    Returns:
        Whatever sits at the end of the path.
    """
    target: Any = client
    for word in route.command:
        target = getattr(target, word)
    return target


def call_arguments(route: Route) -> tuple[tuple[str, ...], dict[str, str]]:
    """Arguments that satisfy a route's signature, one value per filter.

    Args:
        route: The route.

    Returns:
        The positional arguments and the keyword arguments.
    """
    args = (POSITIONAL_VALUES[route.positional],) if route.positional else ()
    return args, {python_name(name): f"{name}-value" for name in route.filters}


def test_the_client_is_importable_from_the_package() -> None:
    assert tmxcaliber.Client is Client
    assert "Client" in tmxcaliber.__all__


def test_a_superseded_release_is_importable_where_every_route_failure_is() -> None:
    # The README promises every route failure from `tmxcaliber`, and a pinned
    # archive request raises this one, so a caller has to be able to catch it.
    from tmxcaliber import ReleaseSuperseded as from_top
    from tmxcaliber.lib.remote import ReleaseSuperseded as from_remote

    assert from_top is from_remote is errors_module.ReleaseSuperseded
    assert "ReleaseSuperseded" in tmxcaliber.__all__
    assert "ReleaseSuperseded" in remote_package.__all__


@pytest.mark.parametrize(
    "command",
    [("threatmodels", "get"), ("ccr", "packs", "get")],
    ids=lambda command: " ".join(command),
)
def test_a_route_method_raises_the_apis_not_found_with_no_other_call(
    command: tuple[str, ...],
) -> None:
    # The command line reads a list to suggest a name; the library makes only
    # the calls its caller wrote, so its route methods do not.
    missing = {"error": {"code": "not_found", "message": "Not found."}}
    opener = FakeOpener([http_error(404, missing)])
    route = route_for(command)
    assert route is not None

    with pytest.raises(errors_module.NotFound) as caught:
        operation_for(Client(opener=opener), route)("aws-ec3")

    assert str(caught.value) == "Not found."
    assert len(opener.requests) == 1


@pytest.mark.parametrize(
    ("typed", "segment"),
    [
        ("aws-s3", "aws-s3"),
        ("Gemini Agent Platform", "Gemini%20Agent%20Platform"),
        ("pub/sub", "pub%2Fsub"),
        ("what?x=1", "what%3Fx%3D1"),
        ("a#b", "a%23b"),
        ("line\nbreak", "line%0Abreak"),
        ("café", "caf%C3%A9"),
    ],
)
def test_a_pack_name_fills_one_path_segment_whatever_it_holds(
    typed: str, segment: str
) -> None:
    # A name is typed by a person, so it may hold a space, a slash or a mark
    # that would end the path, and none of those may reach the request line.
    for command, suffix in (
        (("ccr", "packs", "get"), ""),
        (("ccr", "packs", "archive"), "/archive"),
    ):
        route = route_for(command)
        assert route is not None

        path, query = request_for(route, typed, {})

        assert path == f"/v1/ccr/packs/{segment}{suffix}"
        assert query == {name: "" for name in route.filters}


@pytest.mark.parametrize(
    "command", [("ccr", "packs", "get"), ("ccr", "packs", "archive")], ids=" ".join
)
def test_a_pack_name_with_spaces_gets_the_apis_not_found_not_a_lost_connection(
    command: tuple[str, ...],
) -> None:
    # Without the encoding the transport refuses the path before sending it,
    # and the client reports a lost connection after retrying three times.
    missing = {"error": {"code": "not_found", "message": "Not found."}}
    opener = StrictOpener([http_error(404, missing)])
    route = route_for(command)
    assert route is not None

    with pytest.raises(errors_module.NotFound):
        operation_for(Client(opener=opener), route)("Gemini Agent Platform")

    [sent] = opener.requests
    assert "Gemini%20Agent%20Platform" in sent.full_url
    assert " " not in sent.full_url


@pytest.mark.parametrize("route", routes(), ids=lambda route: " ".join(route.command))
def test_every_route_sits_at_its_cli_command_path(route: Route) -> None:
    client = Client()

    found = operation_for(client, route)

    assert isinstance(found, Operation)
    assert found.__doc__ == route.summary


@pytest.mark.parametrize("route", routes(), ids=lambda route: " ".join(route.command))
def test_every_route_calls_its_own_path_with_its_filters(route: Route) -> None:
    # Arrange
    answer = (
        FakeBytesResponse(ZIP)
        if route.binary
        else FakeResponse(page(route, []) if route.paged else {})
    )
    opener = FakeOpener([answer])
    client = Client(opener=opener)
    args, kwargs = call_arguments(route)
    wire = {name: kwargs[python_name(name)] for name in route.filters}
    expected_path, expected_query = request_for(route, args[0] if args else "", wire)

    # Act
    operation_for(client, route)(*args, **kwargs)

    # Assert
    sent = urllib.parse.urlsplit(opener.requests[0].full_url)
    assert sent.path == expected_path
    assert dict(urllib.parse.parse_qsl(sent.query)) == expected_query


@pytest.mark.parametrize("route", routes(), ids=lambda route: " ".join(route.command))
def test_the_signature_reads_like_the_cli_command(route: Route) -> None:
    parameters = inspect.signature(operation_for(Client(), route)).parameters

    names = [name for name in parameters if name not in ("limit", "allow_incomplete")]
    expected = ([route.positional] if route.positional else []) + [
        python_name(name) for name in route.filters
    ]
    assert names == expected
    assert ("limit" in parameters) is route.paged
    assert ("allow_incomplete" in parameters) is bool(incompleteness_fields(route))
    for option in route.options:
        if option.required:
            assert (
                parameters[python_name(option.name)].default is inspect.Parameter.empty
            )


def test_a_paged_route_returns_every_row_across_pages() -> None:
    route = next(
        route for route in routes() if route.command == ("threatmodels", "list")
    )
    opener = FakeOpener(
        [
            FakeResponse(page(route, [{"tmId": "aws-s3"}], cursor="next")),
            FakeResponse(page(route, [{"tmId": "aws-ec2"}])),
        ]
    )

    rows = Client(opener=opener).threatmodels.list(provider="aws", limit=1)

    assert rows == [{"tmId": "aws-s3"}, {"tmId": "aws-ec2"}]
    second = urllib.parse.urlsplit(opener.requests[1].full_url)
    assert dict(urllib.parse.parse_qsl(second.query)) == {
        "provider": "aws",
        "limit": "1",
        "cursor": "next",
    }


def test_python_feature_class_keyword_uses_snake_case() -> None:
    route = next(
        route for route in routes() if route.command == ("threatmodels", "threats")
    )
    opener = FakeOpener([FakeResponse(page(route, []))])
    client = Client(opener=opener)

    client.threatmodels.threats("aws-s3", feature_class_id="S3.FC1")

    sent = urllib.parse.urlsplit(opener.requests[0].full_url)
    assert dict(urllib.parse.parse_qsl(sent.query))["featureClassId"] == "S3.FC1"
    with pytest.raises(TypeError):
        client.threatmodels.threats("aws-s3", featureClassId="S3.FC1")


def test_a_pinned_reference_sends_its_release() -> None:
    route = next(
        route for route in routes() if route.path_parameters == REFERENCE_PARAMETERS
    )
    answer = page(route, []) if route.paged else {}
    opener = FakeOpener([FakeResponse(answer)])

    operation_for(Client(opener=opener), route)("aws-s3@1611187200")

    sent = urllib.parse.urlsplit(opener.requests[0].full_url)
    assert dict(urllib.parse.parse_qsl(sent.query))["release"] == "1611187200"


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        pytest.param((), {}, id="positional missing"),
        pytest.param(("aws-s3",), {"severity": "high"}, id="unknown filter"),
        pytest.param(("aws-s3", "extra"), {}, id="second positional"),
    ],
)
def test_arguments_the_route_does_not_take_are_refused(
    args: tuple[str, ...], kwargs: dict[str, str]
) -> None:
    opener = FakeOpener([])

    with pytest.raises(TypeError):
        Client(opener=opener).threatmodels.threats(*args, **kwargs)

    assert opener.requests == []


def test_a_required_filter_cannot_be_left_out() -> None:
    route = next(
        route for route in routes() if any(option.required for option in route.options)
    )
    opener = FakeOpener([])

    with pytest.raises(TypeError, match="missing a required"):
        operation_for(Client(opener=opener), route)()

    assert opener.requests == []


def incomplete_route() -> Route:
    """Find a route whose pages can report rows they could not resolve.

    Returns:
        The first such route.
    """
    return next(route for route in routes() if incompleteness_fields(route))


def test_an_incomplete_answer_is_refused_with_its_rows() -> None:
    # Arrange
    route = incomplete_route()
    body = page(route, [{"id": "row-1"}])
    field = incompleteness_fields(route)[0]
    body[field] = ["aws-gone"]
    client = Client(opener=FakeOpener([FakeResponse(body)]))
    args, kwargs = call_arguments(route)

    # Act
    with pytest.raises(IncompleteAnswer, match="aws-gone") as raised:
        operation_for(client, route)(*args, **kwargs)

    # Assert
    assert raised.value.result == [{"id": "row-1"}]
    assert raised.value.envelope[field] == ["aws-gone"]


def test_an_incomplete_answer_is_returned_when_the_caller_allows_it() -> None:
    route = incomplete_route()
    body = page(route, [{"id": "row-1"}])
    body[incompleteness_fields(route)[0]] = ["aws-gone"]
    client = Client(opener=FakeOpener([FakeResponse(body)]))
    args, kwargs = call_arguments(route)

    rows = operation_for(client, route)(*args, allow_incomplete=True, **kwargs)

    assert rows == [{"id": "row-1"}]


def test_with_no_arguments_the_key_resolves_as_the_cli_resolves_it() -> None:
    client = Client()

    assert client.key_id == KEY.split("-")[2]
    assert client.base_url == DEFAULT_BASE_URL


def test_arguments_win_over_the_environment() -> None:
    client = Client(OTHER, "https://api.example.org")

    assert client.key_id == OTHER.split("-")[2]
    assert client.base_url == "https://api.example.org"


def test_with_no_key_anywhere_the_client_says_where_to_put_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TOC_API_KEY")

    with pytest.raises(ConfigurationError, match="TOC_API_KEY"):
        Client()


def test_a_key_and_an_endpoint_given_together_never_read_the_file(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A group-readable file is refused when it is read, so reading it here
    # would raise.
    shared = write_config(tmp_path / "credentials", f"[default]\napi_key = {KEY}\n")
    shared.chmod(0o644)
    monkeypatch.setenv("TOC_CONFIG_FILE", str(shared))

    client = Client(OTHER, "https://api.example.org")

    assert client.base_url == "https://api.example.org"


def test_an_environment_key_going_to_a_stored_endpoint_warns(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in HAZARD.environment(tmp_path).items():
        monkeypatch.setenv(name, value)

    with pytest.warns(UserWarning, match="key in TOC_API_KEY") as caught:
        client = Client()

    assert client.base_url == STORED_URL
    assert caught[0].filename == __file__


def test_an_argument_key_going_to_a_stored_endpoint_warns_in_its_own_terms(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write_config(
        tmp_path / "credentials",
        f"[default]\napi_key = {KEY}\napi_url = {STORED_URL}\n",
    )
    monkeypatch.setenv("TOC_CONFIG_FILE", str(config))

    with pytest.warns(UserWarning, match="passed as api_key.*Pass api_url"):
        Client(OTHER)


def test_a_chosen_endpoint_does_not_warn(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in HAZARD.environment(tmp_path).items():
        monkeypatch.setenv(name, value)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        client = Client(api_url="https://api.example.org")

    assert client.base_url == "https://api.example.org"


def test_a_command_word_that_would_hide_a_client_attribute_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clash = Route(
        path="/v1/get",
        command=("get",),
        paged=False,
        options=(),
        path_parameters=(),
        positional=None,
        summary="A route whose command would hide Client.get.",
    )
    monkeypatch.setattr(api_module, "routes", lambda: (*routes(), clash))

    with pytest.raises(ValueError, match="'get' is already taken"):
        Client()


def test_a_group_lists_what_it_holds() -> None:
    group = Client().threatmodels

    assert isinstance(group, Group)
    assert repr(group).startswith("<threatmodels: ")
    assert "threats" in repr(group)


def test_a_binary_route_returns_the_bytes() -> None:
    body = b"PK\x03\x04\xff"
    client = Client(opener=FakeOpener([FakeBytesResponse(body)]))

    assert client.ccr.packs.archive("aws-s3", kind="deploy") == body


def test_a_binary_route_refuses_the_json_a_sibling_route_would_answer() -> None:
    # A path that lands on the manifest route answers 200 JSON. Handed back as
    # the archive it would be written out as a zip that is not one.
    served = FakeResponse({"rules": []}, {"Content-Type": "application/json"})
    client = Client(opener=FakeOpener([served]))

    with pytest.raises(ContractViolation, match="contract publishes application/zip"):
        client.ccr.packs.archive("aws-s3")

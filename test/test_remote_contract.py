"""Hold the interpreted commands to the vendored contract and to what shipped.

**These are the checks the client cannot do on its own.** Every other test
here mocks the transport, so they only ever compare the client against
itself. These read the vendored document: that every route it publishes is
reachable, and that refreshing it has not taken away a command a caller
already relies on.
"""

from __future__ import annotations

from typing import Any, Final

import pytest

from tmxcaliber.lib.remote import contract

#: Every command 0.7 shipped: its positional, and each option with whether it
#: was required.
#:
#: A frozen record of a published surface rather than a copy of the contract,
#: so it never needs editing when the API adds something. It fails only when a
#: refreshed contract removes or renames a command, a positional or an option,
#: or makes an option required: the breaks the API's v1 compatibility promise
#: rules out, and the ones a caller would otherwise discover as a usage error.
RELEASED: Final[dict[tuple[str, ...], tuple[str | None, dict[str, bool]]]] = {
    ("apis", "list"): (None, {}),
    ("apis", "openapi"): (None, {}),
    ("me",): (None, {}),
    ("threatmodels", "list"): (None, {"provider": False}),
    ("threatmodels", "get"): ("tm_id", {"release": False}),
    ("threatmodels", "threats"): (
        "tm_id",
        {"featureClassId": False, "release": False},
    ),
    ("threatmodels", "controls"): (
        "tm_id",
        {"featureClassId": False, "release": False},
    ),
    ("threatmodels", "actions"): (
        "tm_id",
        {"featureClassId": False, "release": False},
    ),
    ("threatmodels", "dfd"): ("tm_id", {"release": False}),
    ("subscriptions", "list"): (None, {}),
    ("compliance", "frameworks", "list"): (None, {}),
    ("compliance", "mappings", "list"): (None, {"frameworkId": True, "tmId": False}),
    ("ccr", "packs", "list"): (None, {}),
    ("ccr", "packs", "get"): ("tm_id", {}),
}


def test_every_documented_route_has_a_command() -> None:
    """No published route is unreachable, apart from the named omissions."""
    bound = {route.path for route in contract.routes()}

    assert bound == contract.documented_paths() - contract.UNBOUND


@pytest.mark.parametrize(
    ("command", "released"), RELEASED.items(), ids=lambda value: str(value)
)
def test_a_released_command_survives_the_contract(
    command: tuple[str, ...], released: tuple[str | None, dict[str, bool]]
) -> None:
    """A refreshed contract keeps every command, positional and option 0.7 had."""
    positional, options = released

    route = contract.route_for(command)

    assert route is not None, f"`{' '.join(command)}` is gone"
    assert route.positional == positional
    required = {option.name: option.required for option in route.options}
    for name, was_required in options.items():
        assert name in required, f"`{' '.join(command)}` lost --{name}"
        assert required[name] is was_required, f"--{name} changed requiredness"
    added = [name for name in required if name not in options and required[name]]
    assert added == [], f"`{' '.join(command)}` now requires {added}"


@pytest.mark.parametrize("route", contract.routes(), ids=lambda r: r.path)
def test_declared_filters_match_the_contract(route: contract.Route) -> None:
    """A route's options are exactly its documented query parameters.

    `limit` and `cursor` are excluded because they are pagination mechanics
    the client owns: the caller asks for a collection and gets all of it.
    """
    documented = contract.query_parameters(route.path) - contract.PAGING_PARAMETERS

    assert set(route.filters) == documented


@pytest.mark.parametrize("route", contract.routes(), ids=lambda r: r.path)
def test_every_filter_is_described_by_the_contract(route: contract.Route) -> None:
    """An option's help is its parameter's description, so each needs one."""
    for name in route.filters:
        described = contract.query_parameter(route.path, name).get("description")
        assert described, f"{route.path} publishes no description for {name}"


@pytest.mark.parametrize("route", contract.routes(), ids=lambda r: r.path)
def test_paged_matches_the_contract(route: contract.Route) -> None:
    """A route is walked if, and only if, the contract pages it."""
    assert route.paged is (contract.page_maximum(route.path) is not None)


def test_the_vendored_contract_is_the_published_one() -> None:
    """The vendored document is a v1 contract for this API."""
    document = contract.contract()
    assert document["openapi"].startswith("3.")
    assert all(path.startswith("/v1/") for path in document["paths"])


def _row_properties(path: str) -> set[str]:
    """Read the fields of one paged route's rows from the contract.

    Args:
        path: The OpenAPI path template.

    Returns:
        The property names of the row schema.
    """
    document: dict[str, Any] = contract.contract()
    response = document["paths"][path]["get"]["responses"]["200"]
    schema = response["content"]["application/json"]["schema"]
    items = next(part for part in schema["allOf"] if "properties" in part)
    reference = items["properties"]["items"]["items"]["$ref"]
    row = document["components"]["schemas"][reference.rsplit("/", 1)[-1]]
    return set(row["properties"])


def test_the_framework_filter_names_the_frameworks_list() -> None:
    """A required filter with no hint is what made `mappings list` a dead end."""
    mappings = contract.route_for(("compliance", "mappings", "list"))
    assert mappings is not None

    lookup = contract.values_route(mappings, "frameworkId")

    assert lookup is not None
    assert lookup.command == ("compliance", "frameworks", "list")
    assert contract.values_field("frameworkId") == "frameworkId"


@pytest.mark.parametrize("route", contract.routes(), ids=lambda r: r.path)
def test_every_values_route_carries_the_field_it_is_cited_for(
    route: contract.Route,
) -> None:
    """The help names a field; the listing it points at must have that field."""
    for name in route.filters:
        lookup = contract.values_route(route, name)
        if lookup is None:
            continue
        field = contract.values_field(name)
        assert field in _row_properties(lookup.path), (
            f"{route.path} --{name} cites {lookup.path} rows for {field}, "
            "which they do not carry"
        )


def test_values_field_uses_the_api_spelling() -> None:
    """Multi-word filters keep the API's camelCase spelling."""
    assert contract.values_field("featureClassId") == "featureClassId"


def test_the_mappings_route_requires_its_completeness_field() -> None:
    """The compliance mappings page must say which ThreatModels it could not resolve."""
    assert contract.required_page_fields("/v1/compliance/mappings") == {
        "unresolvedTmIds": (list,)
    }


def test_every_incompleteness_field_is_required_by_some_route() -> None:
    """A name the CLI and Client watch for must be one the contract requires."""
    from tmxcaliber.lib.remote.operations import INCOMPLETENESS_FIELDS

    required = {
        name
        for route in contract.routes()
        for name in contract.required_page_fields(route.path)
    }
    assert set(INCOMPLETENESS_FIELDS) <= required


def test_paging_fields_come_from_the_page_schema() -> None:
    """The client walks by these, so they are read from the contract, not restated."""
    assert contract.paging_fields() == {"items", "nextCursor", "pageSize"}


@pytest.mark.parametrize("route", contract.routes(), ids=lambda r: r.path)
def test_binary_matches_the_contract(route: contract.Route) -> None:
    """A route is binary exactly when the contract serves its 200 as a zip."""
    served = contract.response_media_type(route.path)
    assert route.binary is (served == "application/zip")


def test_the_pack_archive_is_a_binary_command() -> None:
    route = contract.route_for(("ccr", "packs", "archive"))

    assert route is not None
    assert route.binary is True
    assert route.path == "/v1/ccr/packs/{tmId}/archive"
    assert route.filters == ("kind", "release")
    assert route.positional == "tm_id"


def test_the_pack_archive_is_bound_once_and_left_out_of_unbound() -> None:
    """The binary transport binds the archive, so no omission excuses it."""
    archives = [r for r in contract.routes() if r.path.endswith("/archive")]

    assert [r.path for r in archives] == ["/v1/ccr/packs/{tmId}/archive"]
    assert not contract.UNBOUND


def test_a_pack_row_names_its_release() -> None:
    assert "releaseId" in _row_properties("/v1/ccr/packs")


def test_the_pack_list_summary_names_the_product_as_the_contract_does() -> None:
    # The summary is the command's help, so wording of the client's own can
    # name a product other than the one the contract describes.
    route = contract.route_for_path("/v1/ccr/packs")
    published = contract.contract()["paths"]["/v1/ccr/packs"]["get"]["summary"]

    assert route is not None
    assert route.summary == published


@pytest.mark.parametrize("path", ["/v1/me", "/v1/threatmodels", "/v1/subscriptions"])
def test_the_credential_scoped_summaries_say_what_the_contract_says(path: str) -> None:
    # The summary is the command's help. The contract scopes these routes to
    # the credential, which can act for a person, where it used to say tenant.
    route = contract.route_for_path(path)
    published = contract.contract()["paths"][path]["get"]["summary"]

    assert route is not None
    assert route.summary == published

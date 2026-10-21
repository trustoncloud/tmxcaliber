"""Hold the client's command table and the vendored contract in agreement.

**This is the check the client cannot do on its own.** Every other test here
mocks the transport, so they only ever compare the client against itself: a
command naming a route the API does not serve stays green forever, and the
caller discovers it as a 404.

Both directions catch something real. A documented route with no command is
a capability the API published and this tool silently does not expose. A
command naming no documented route is a 404 waiting for whoever runs it.
"""

from __future__ import annotations

import pytest

from tmxcaliber.lib.remote import contract


def test_every_command_names_a_documented_route() -> None:
    """No command points at a route the contract does not publish."""
    documented = contract.documented_paths()
    unknown = sorted(r.path for r in contract.ROUTES if r.path not in documented)
    assert unknown == [], f"commands name undocumented routes: {unknown}"


def test_every_documented_route_has_a_command() -> None:
    """No published route is unreachable through the CLI."""
    bound = {r.path for r in contract.ROUTES} | contract.UNBOUND
    missing = sorted(contract.documented_paths() - bound)
    assert missing == [], f"documented routes with no command: {missing}"


def test_the_unbound_list_has_no_stale_entries() -> None:
    """Every deliberate omission still names a route that exists.

    An entry that has since gained a command, or names a route the API
    dropped, is an excuse that outlived its reason.
    """
    documented = contract.documented_paths()
    bound = {r.path for r in contract.ROUTES}
    for path in contract.UNBOUND:
        assert path in documented, f"{path} is not a documented route"
        assert path not in bound, f"{path} is both bound and listed as unbound"


def test_commands_are_unique() -> None:
    """Two routes cannot answer to the same command."""
    commands = [r.command for r in contract.ROUTES]
    assert len(commands) == len(set(commands)), "two routes share a command"


@pytest.mark.parametrize("route", contract.ROUTES, ids=lambda r: r.path)
def test_declared_filters_match_the_contract(route: contract.Route) -> None:
    """A route's options are exactly its documented query parameters.

    `limit` and `cursor` are excluded because they are pagination mechanics
    the client owns: the caller asks for a collection and gets all of it.
    """
    documented = contract.query_parameters(route.path) - {"limit", "cursor"}
    assert set(route.filters) == documented, (
        f"{route.path} declares {sorted(route.filters)} "
        f"but the contract documents {sorted(documented)}"
    )


@pytest.mark.parametrize("route", contract.ROUTES, ids=lambda r: r.path)
def test_paged_matches_the_contract(route: contract.Route) -> None:
    """A route is walked if, and only if, the contract pages it."""
    assert route.paged is (contract.page_maximum(route.path) is not None), (
        f"{route.path} is declared paged={route.paged}"
    )


@pytest.mark.parametrize("route", contract.ROUTES, ids=lambda r: r.path)
def test_path_parameters_are_filled(route: contract.Route) -> None:
    """Every path parameter is supplied by the command's positional."""
    placeholders = route.path.count("{")
    if placeholders == 0:
        assert route.positional is None, f"{route.path} takes no path parameter"
    else:
        assert route.positional is not None, (
            f"{route.path} has {placeholders} path parameters and no positional"
        )


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
    document = contract.contract()
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


@pytest.mark.parametrize("route", contract.ROUTES, ids=lambda r: r.path)
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
    assert contract.values_field("featureClass") == "featureClassId"


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
        for route in contract.ROUTES
        for name in contract.required_page_fields(route.path)
    }
    assert set(INCOMPLETENESS_FIELDS) <= required


def test_paging_fields_come_from_the_page_schema() -> None:
    """The client walks by these, so they are read from the contract, not restated."""
    assert contract.paging_fields() == {"items", "nextCursor", "pageSize"}


@pytest.mark.parametrize("route", contract.ROUTES, ids=lambda r: r.path)
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
    archives = [r for r in contract.ROUTES if r.path.endswith("/archive")]

    assert [r.path for r in archives] == ["/v1/ccr/packs/{tmId}/archive"]
    assert not contract.UNBOUND


def test_a_pack_row_names_its_release() -> None:
    assert "releaseId" in _row_properties("/v1/ccr/packs")


def test_a_pack_row_names_its_pack_by_tm_id_alone() -> None:
    """`ccr fetch` reads the provider and service from the id.

    The row once carried a ``service`` beside a ``releaseKey``. Both are gone,
    so narrowing by provider or service has only ``tmId`` to go on.
    """
    fields = _row_properties("/v1/ccr/packs")

    assert "tmId" in fields
    assert not fields & {"releaseKey", "service"}


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

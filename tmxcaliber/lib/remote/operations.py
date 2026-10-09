"""How one route becomes one request, for the CLI and for `Client` alike.

Both surfaces are built from `contract.ROUTES`, and both need the same three
answers for a route: which concrete path a positional fills in, which query
it sends, and whether the rows that came back are whole. Giving those one
owner here is what keeps ``tmxcaliber threatmodels threats aws-s3`` and
``Client().threatmodels.threats("aws-s3")`` from drifting apart.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .client import TocClient
from .contract import Route, required_page_fields
from .ref import parse_ref

#: Page fields that, when not empty, mean the rows are incomplete.
#:
#: The contract says so in each field's description; the code cannot read that,
#: so the names live here, and a test holds each to a route that requires it.
INCOMPLETENESS_FIELDS: Final[tuple[str, ...]] = ("unresolvedTmIds",)


@dataclass(frozen=True)
class Answer:
    """What one route returned.

    Attributes:
        result: Every row of a paged route, or the object of any other.
        envelope: A paged route's first-page fields other than the paging
            ones; empty for any other route.
        missing: One ``name: value`` line per incompleteness field the API
            reported as not empty. Empty means the rows are whole.
    """

    result: Any
    envelope: dict[str, Any] = field(default_factory=dict)
    missing: tuple[str, ...] = ()


def incompleteness_fields(route: Route) -> tuple[str, ...]:
    """List the incompleteness fields a route's pages are required to carry.

    Args:
        route: The route.

    Returns:
        The names, in ``INCOMPLETENESS_FIELDS`` order.
    """
    required = required_page_fields(route.path)
    return tuple(name for name in INCOMPLETENESS_FIELDS if name in required)


def request_for(
    route: Route, positional: str, filters: Mapping[str, str]
) -> tuple[str, dict[str, str]]:
    """Fill a route's path and query from what the caller gave.

    Args:
        route: The route.
        positional: The value of the route's positional, or empty when it
            has none.
        filters: Values for the route's filters, by name. Absent and empty
            filters are not sent.

    Returns:
        The concrete path, and the query to send with it.

    Raises:
        ValueError: If a ThreatModel reference cannot be parsed.
    """
    path = route.path
    query = {name: filters.get(name, "") for name in route.filters}
    if route.positional == "tm_id":
        ref = parse_ref(positional)
        path = path.replace("{provider}", ref.provider).replace(
            "{service}", ref.service
        )
        # `@release` is sugar for the query parameter, so a caller can pin
        # either way and only one of them reaches the wire.
        if ref.release and not query.get("release"):
            query["release"] = ref.release
    elif route.positional == "release_key":
        path = path.replace("{releaseKey}", positional)
    return path, query


def call_route(
    client: TocClient,
    route: Route,
    positional: str,
    filters: Mapping[str, str],
    limit: int = 0,
) -> Answer:
    """Call one route, walking every page of a paged one.

    Args:
        client: The client to call through.
        route: The route.
        positional: The value of the route's positional, or empty.
        filters: Values for the route's filters, by name.
        limit: Rows per request for a paged route, or 0 for the server's
            default. The whole collection is read either way.

    Returns:
        The answer, including whether the API reported missing rows.

    Raises:
        RemoteError: On any credential, transport or server failure.
        ValueError: If a ThreatModel reference cannot be parsed.
    """
    path, query = request_for(route, positional, filters)
    if not route.paged:
        return Answer(result=client.get(path, query))

    envelope: dict[str, Any] = {}
    rows = list(
        client.paginate(
            path,
            query,
            page_size=limit,
            envelope=envelope,
            required=required_page_fields(route.path),
        )
    )
    missing = tuple(
        f"{name}: {json.dumps(envelope[name])}"
        for name in incompleteness_fields(route)
        if envelope.get(name)
    )
    return Answer(result=rows, envelope=envelope, missing=missing)

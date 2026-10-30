"""How one route becomes one request, for the CLI and for `Client` alike.

Both surfaces are built from `contract.routes()`, and both need the same three
answers for a route: which concrete path a positional fills in, which query
it sends, and whether the rows that came back are whole. Giving those one
owner here is what keeps ``tmxcaliber threatmodels threats aws-s3`` and
``Client().threatmodels.threats("aws-s3")`` from drifting apart.
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .client import TocClient
from .contract import (
    REFERENCE_PARAMETERS,
    RELEASE_OPTION,
    Route,
    required_page_fields,
    response_media_type,
)
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
        result: Every row of a paged route, the bytes of a binary one, or the
            object of any other.
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
        The concrete path, with a pack's ThreatModel id percent-encoded as
        one path segment, and the query to send with it.

    Raises:
        ValueError: If a ThreatModel reference cannot be parsed, or is pinned
            for a route that takes no release.
    """
    path = route.path
    query = {name: filters.get(name, "") for name in route.filters}
    if route.path_parameters == REFERENCE_PARAMETERS:
        ref = parse_ref(positional)
        path = path.replace("{provider}", ref.provider).replace(
            "{service}", ref.service
        )
        # `@release` is sugar for the query parameter, so a caller can pin
        # either way and only one of them reaches the wire. The API refuses a
        # parameter a route does not declare, so a route without the option
        # cannot be pinned at all.
        if ref.release and RELEASE_OPTION not in route.filters:
            raise ValueError(
                f"`{' '.join(route.command)}` takes no release, so "
                f"{positional!r} cannot be pinned."
            )
        if ref.release and not query.get(RELEASE_OPTION):
            query[RELEASE_OPTION] = ref.release
    elif route.path_parameters:
        (name,) = route.path_parameters
        # A pack's ThreatModel id is typed by a person, and what they type may
        # be a product's name with spaces in it, or hold a slash or a question
        # mark. Left as typed, the transport refuses the path before sending
        # anything, which the client reports as a lost connection and retries,
        # a name that was only wrong never reaches the API's own 404, and a
        # slash could reach another route. One encoded segment is a name the
        # API can answer for, however odd.
        path = path.replace(f"{{{name}}}", urllib.parse.quote(positional, safe=""))
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
        ValueError: If a ThreatModel reference cannot be parsed, or is pinned
            for a route that takes no release.
    """
    path, query = request_for(route, positional, filters)
    if route.binary:
        # Held to the type the contract publishes, so the transport can tell
        # the archive asked for from a body that only carries its label.
        media_type = response_media_type(route.path)
        assert media_type is not None, f"{route.path} publishes no 200 content"
        return Answer(result=client.get_bytes(path, query, media_type=media_type))
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

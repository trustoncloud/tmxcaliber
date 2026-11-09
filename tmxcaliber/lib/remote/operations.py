"""How one route becomes one request, for the CLI and for `Client` alike.

Both surfaces are built from one `contract.Contract`'s routes, and both need
the same three answers for a route: which concrete path a positional fills in,
which query it sends, and whether the rows that came back are whole. Giving
those one owner here is what keeps ``tmxcaliber threatmodels threats aws-s3``
and ``Client().threatmodels.threats("aws-s3")`` from drifting apart.

Everything a call needs from the contract travels on the `Route` itself, so a
route bound from the API's live definition is executed by what that
definition says rather than by the vendored copy.
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .client import QueryValue, TocClient
from .contract import REFERENCE_PARAMETERS, RELEASE_OPTION, Route, paging_fields
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
    required = dict(route.page_fields)
    return tuple(name for name in INCOMPLETENESS_FIELDS if name in required)


def wire(value: object, *, repeatable: bool = False) -> QueryValue:
    """Spell one option's value as the query carries it, for either surface.

    Args:
        value: The value given; None or empty when the option was not given.
            For a repeatable option, one value or a list or tuple of them.
        repeatable: Whether the option takes several values.

    Returns:
        The value as text, or for a repeatable option a tuple of texts with
        the empty ones dropped; empty when nothing was given.
    """
    if repeatable:
        values = value if isinstance(value, (list, tuple)) else (value,)
        return tuple(str(item) for item in values if item is not None and item != "")
    return "" if value is None or value == "" else str(value)


def request_for(
    route: Route, positional: str, filters: Mapping[str, QueryValue]
) -> tuple[str, dict[str, QueryValue]]:
    """Fill a route's path and query from what the caller gave.

    Args:
        route: The route.
        positional: The value of the route's positional, or empty when it
            has none.
        filters: Values for the route's filters, by name, with a tuple for
            one that repeats. Absent and empty filters are not sent.

    Returns:
        The concrete path, with a pack's ThreatModel id percent-encoded as
        one path segment, and the query to send with it.

    Raises:
        ValueError: If a ThreatModel reference cannot be parsed, or is pinned
            for a route that takes no release.
    """
    path = route.path
    query: dict[str, QueryValue] = {
        name: filters.get(name, "") for name in route.filters
    }
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


def page_size(route: Route, limit: int = 0) -> int:
    """Choose how many rows each request for a paged route asks for.

    The largest page the contract permits, unless the caller chose one. The
    server's own default is smaller, and every request draws on the same
    hourly budget, so a walk at the server's default spent several times the
    calls on the same rows; on the OverWatch list it used most of a key's
    hourly budget.

    Args:
        route: The route.
        limit: The caller's choice, or 0 for none.

    Returns:
        The page size to send, or 0 when the route states no maximum and the
        caller chose none, which leaves the server's default.
    """
    return limit or route.page_maximum or 0


def call_route(
    client: TocClient,
    route: Route,
    positional: str,
    filters: Mapping[str, QueryValue],
    limit: int = 0,
) -> Answer:
    """Call one route, walking every page of a paged one.

    Args:
        client: The client to call through.
        route: The route.
        positional: The value of the route's positional, or empty.
        filters: Values for the route's filters, by name.
        limit: Rows per request for a paged route, or 0 for the largest the
            contract permits. The whole collection is read either way.

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
        return Answer(result=client.get_bytes(path, query, media_type=route.media_type))
    if not route.paged:
        return Answer(result=client.get(path, query))

    envelope: dict[str, Any] = {}
    rows = list(
        client.paginate(
            path,
            query,
            page_size=page_size(route, limit),
            envelope=envelope,
            required=dict(route.page_fields),
        )
    )
    return Answer(result=rows, envelope=envelope, missing=_missing(route, envelope))


def read_page(
    client: TocClient,
    route: Route,
    positional: str,
    filters: Mapping[str, QueryValue],
    *,
    limit: int = 0,
    cursor: str = "",
) -> Answer:
    """Read one page of a paged route, for a caller who walks it themselves.

    Args:
        client: The client to call through.
        route: The route, which must be paged.
        positional: The value of the route's positional, or empty.
        filters: Values for the route's filters, by name. A cursor is bound to
            them, so a later page needs the ones its first was read with.
        limit: Rows in the page, or 0 for the largest the contract permits.
        cursor: A previous page's ``nextCursor``, or empty for the first page.

    Returns:
        The answer, whose result is the page as the API served it, with its
        ``items`` and its ``nextCursor`` (null on the last page).

    Raises:
        ValueError: If the route is not paged, or as `request_for` does.
        RemoteError: On any credential, transport or server failure,
            including `InvalidCursor` for a cursor the API does not accept.
    """
    if not route.paged:
        raise ValueError(f"`{' '.join(route.command)}` is not paged.")
    path, query = request_for(route, positional, filters)
    body = client.page(
        path,
        query,
        page_size=page_size(route, limit),
        cursor=cursor,
        required=dict(route.page_fields),
    )
    envelope = {k: v for k, v in body.items() if k not in paging_fields()}
    return Answer(result=body, envelope=envelope, missing=_missing(route, envelope))


def _missing(route: Route, envelope: Mapping[str, Any]) -> tuple[str, ...]:
    """Name what a page reported it could not resolve.

    Args:
        route: The route the page came from.
        envelope: The page's fields other than the paging ones.

    Returns:
        One ``name: value`` line per incompleteness field that is not empty.
    """
    return tuple(
        f"{name}: {json.dumps(envelope[name])}"
        for name in incompleteness_fields(route)
        if envelope.get(name)
    )

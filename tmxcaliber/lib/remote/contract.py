"""The API routes this client binds, and the contract they are held to.

**Naming is derived, never invented.** Every group, command and option name
below comes from the API's own route registry by one mechanical rule, so
nothing here is a naming decision that could be argued about separately:

* the literal path segments after ``/v1`` become the command groups;
* a paged collection takes the verb ``list``;
* a route ending in path parameters takes the verb ``get``;
* a sub-resource of a parameterized route takes its own last segment as the
  command, because the API already says whether it is plural;
* path parameters become one positional, and query parameters become options.

The table is checked against the vendored OpenAPI document in both
directions, so a route the API adds is a missing command rather than a quiet
omission, and a command naming a route the API dropped is a failure rather
than a 404 for whoever runs it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Final

#: Where the pinned copy of the contract lives inside the package.
#:
#: Vendored rather than fetched. ``/v1/apis/openapi.json`` sits behind both
#: authentication and the tenant feature flag, so a client cannot read the
#: contract it is about to call without already being configured for it.
CONTRACT_PACKAGE: Final[str] = "tmxcaliber.lib.remote.openapi"
CONTRACT_FILE: Final[str] = "v1.json"


@dataclass(frozen=True)
class Route:
    """One API route, and the command that reaches it.

    Attributes:
        path: The OpenAPI path template.
        command: The argv words that select it, after the program name.
        paged: Whether the response is a page envelope this client walks.
        filters: Query parameters other than ``limit`` and ``cursor``.
        positional: What the command's positional argument holds, if any.
        summary: One line, for the command's help.
    """

    path: str
    command: tuple[str, ...]
    paged: bool
    filters: tuple[str, ...]
    positional: str | None
    summary: str


#: Every route, bound to the command that reaches it.
ROUTES: Final[tuple[Route, ...]] = (
    Route(
        path="/v1/apis",
        command=("apis", "list"),
        paged=True,
        filters=(),
        positional=None,
        summary="API definitions this credential can reach.",
    ),
    Route(
        path="/v1/apis/openapi.json",
        command=("apis", "openapi"),
        paged=False,
        filters=(),
        positional=None,
        summary="The live contract document, as the API serves it.",
    ),
    Route(
        path="/v1/me",
        command=("me",),
        paged=False,
        filters=(),
        positional=None,
        summary="The calling credential: its tenant, and what it may do.",
    ),
    Route(
        path="/v1/threatmodels",
        command=("threatmodels", "list"),
        paged=True,
        filters=("provider",),
        positional=None,
        summary="ThreatModels this tenant is entitled to.",
    ),
    Route(
        path="/v1/threatmodels/{provider}/{service}",
        command=("threatmodels", "get"),
        paged=False,
        filters=("release",),
        positional="tm_id",
        summary="One ThreatModel, without the sections served separately.",
    ),
    Route(
        path="/v1/threatmodels/{provider}/{service}/threats",
        command=("threatmodels", "threats"),
        paged=True,
        filters=("feature_class", "release"),
        positional="tm_id",
        summary="A ThreatModel's threats.",
    ),
    Route(
        path="/v1/threatmodels/{provider}/{service}/controls",
        command=("threatmodels", "controls"),
        paged=True,
        filters=("feature_class", "release"),
        positional="tm_id",
        summary="A ThreatModel's controls.",
    ),
    Route(
        path="/v1/threatmodels/{provider}/{service}/actions",
        command=("threatmodels", "actions"),
        paged=True,
        filters=("feature_class", "release"),
        positional="tm_id",
        summary="A ThreatModel's actions.",
    ),
    Route(
        path="/v1/threatmodels/{provider}/{service}/dfd",
        command=("threatmodels", "dfd"),
        paged=False,
        filters=("release",),
        positional="tm_id",
        summary="A ThreatModel's data flow diagram.",
    ),
    Route(
        path="/v1/subscriptions",
        command=("subscriptions", "list"),
        paged=True,
        filters=(),
        positional=None,
        summary="What this tenant is entitled to, and until when.",
    ),
    Route(
        path="/v1/compliance/frameworks",
        command=("compliance", "frameworks", "list"),
        paged=True,
        filters=(),
        positional=None,
        summary="Compliance frameworks.",
    ),
    Route(
        path="/v1/compliance/mappings",
        command=("compliance", "mappings", "list"),
        paged=True,
        filters=("framework", "service"),
        positional=None,
        summary="Framework controls mapped to ThreatModel objectives.",
    ),
    Route(
        path="/v1/ccr/packs",
        command=("ccr", "packs", "list"),
        paged=True,
        filters=(),
        positional=None,
        summary="Wiz Custom Configuration Rule packs.",
    ),
    Route(
        path="/v1/ccr/packs/{releaseKey}",
        command=("ccr", "packs", "get"),
        paged=False,
        filters=(),
        positional="release_key",
        summary="One CCR pack.",
    ),
)


#: Routes the client deliberately does not bind.
#:
#: Empty, and it should stay that way. An entry here is a published route a
#: caller cannot reach through this tool, so each one needs a reason and the
#: list may only ever shrink.
UNBOUND: Final[frozenset[str]] = frozenset()


@lru_cache(maxsize=1)
def contract() -> dict[str, Any]:
    """Load the vendored OpenAPI document.

    Returns:
        The parsed contract.
    """
    text = resources.files(CONTRACT_PACKAGE).joinpath(CONTRACT_FILE).read_text()
    loaded: dict[str, Any] = json.loads(text)
    return loaded


def documented_paths() -> frozenset[str]:
    """List every path the vendored contract publishes.

    Returns:
        The path templates.
    """
    return frozenset(contract()["paths"])


def route_for(command: tuple[str, ...]) -> Route | None:
    """Find the route a command reaches.

    Args:
        command: The argv words after the program name.

    Returns:
        The route, or None when no command matches.
    """
    for route in ROUTES:
        if route.command == command:
            return route
    return None


def page_maximum(path: str) -> int | None:
    """Read a route's largest permitted page size from the contract.

    Walking a collection at its maximum is what keeps a full read inside the
    API's hourly budget, and the maximum is the contract's to state.

    Args:
        path: The OpenAPI path template.

    Returns:
        The maximum, or None when the route is not paged.
    """
    for parameter in (
        contract()["paths"].get(path, {}).get("get", {}).get("parameters", [])
    ):
        if parameter.get("name") == "limit":
            maximum = parameter.get("schema", {}).get("maximum")
            return int(maximum) if maximum is not None else None
    return None


def required_parameters(path: str) -> frozenset[str]:
    """List a route's required query parameters.

    Read from the contract rather than restated, because which parameters a
    route insists on is the API's decision and it has changed once already.

    Args:
        path: The OpenAPI path template.

    Returns:
        The names the route refuses to answer without.
    """
    names = {
        str(parameter["name"])
        for parameter in contract()
        .get("paths", {})
        .get(path, {})
        .get("get", {})
        .get("parameters", [])
        if parameter.get("in") == "query" and parameter.get("required") is True
    }
    return frozenset(names)


def values_route(route: Route, filter_name: str) -> Route | None:
    """Find the route that lists the values one of a route's filters accepts.

    Derived by the same kind of mechanical rule as the command names: the
    paged sibling collection named for the filter's plural. ``framework`` on
    ``/v1/compliance/mappings`` is answered by ``/v1/compliance/frameworks``,
    whose rows carry a ``frameworkId``.

    Args:
        route: The route whose filter is being described.
        filter_name: The query parameter, as the API spells it.

    Returns:
        The listing route, or None when the API publishes no such list.
    """
    parent = route.path.rsplit("/", 1)[0]
    candidate = route_for_path(f"{parent}/{filter_name}s")
    if candidate is None or not candidate.paged or candidate is route:
        return None
    return candidate


def values_field(filter_name: str) -> str:
    """Name the row field of a values route that a filter takes.

    Args:
        filter_name: The query parameter, as the API spells it.

    Returns:
        The field, in the API's camelCase (``framework`` -> ``frameworkId``).
    """
    head, *rest = filter_name.split("_")
    return head + "".join(word.title() for word in rest) + "Id"


def route_for_path(path: str) -> Route | None:
    """Find the route bound to a path template.

    Args:
        path: The OpenAPI path template.

    Returns:
        The route, or None when no route binds that path.
    """
    for route in ROUTES:
        if route.path == path:
            return route
    return None


#: What each JSON Schema type is in Python, for checking a page's own fields.
_JSON_TYPES: Final[dict[str, type | tuple[type, ...]]] = {
    "array": list,
    "boolean": bool,
    "integer": int,
    "null": type(None),
    "number": (int, float),
    "object": dict,
    "string": str,
}


def paging_fields() -> frozenset[str]:
    """List the fields every page carries, as the contract's ``Page`` declares.

    Returns:
        The envelope fields the client walks by, such as ``nextCursor``.
    """
    return frozenset(contract()["components"]["schemas"]["Page"]["required"])


def required_page_fields(path: str) -> dict[str, tuple[type, ...]]:
    """List the fields a route's every page must carry beyond the paging ones.

    Read from the contract's 200 schema, so a field the API makes required,
    such as which ThreatModels a compliance mapping could not resolve, is held
    to without restating it here. A page that omits one is a contract breach,
    not an answer with nothing to report.

    Args:
        path: The OpenAPI path template.

    Returns:
        Each required field and the Python types its value may have; empty
        for a route that is not paged or declares none.
    """
    schema = (
        contract()["paths"]
        .get(path, {})
        .get("get", {})
        .get("responses", {})
        .get("200", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )
    fields: dict[str, tuple[type, ...]] = {}
    for part in schema.get("allOf", []):
        properties = part.get("properties", {})
        for name in part.get("required", []):
            if name in paging_fields():
                continue
            declared = properties.get(name, {}).get("type", [])
            names = declared if isinstance(declared, list) else [declared]
            accepted: list[type] = []
            for json_type in names:
                python = _JSON_TYPES.get(json_type)
                if isinstance(python, tuple):
                    accepted.extend(python)
                elif python is not None:
                    accepted.append(python)
            fields[name] = tuple(accepted) or (object,)
    return fields


def query_parameters(path: str) -> frozenset[str]:
    """List a route's query parameters as the contract declares them.

    Args:
        path: The OpenAPI path template.

    Returns:
        Every query parameter name, including ``limit`` and ``cursor``.
    """
    names = {
        str(parameter["name"])
        for parameter in contract()["paths"]
        .get(path, {})
        .get("get", {})
        .get("parameters", [])
        if parameter.get("in") == "query"
    }
    return frozenset(names)

"""The API's operations, interpreted from an OpenAPI contract.

The contract is the copy vendored with this release unless a caller asks for
the API's live definition (``--contract live``, or ``Client(contract="live")``),
which `live_contract.py` reads for one credential. Either way it becomes one
`Contract`, so a command and its `Client` method stay two views of one route.

**Naming is derived, never invented.** Every group, command and option comes
from the contract by one mechanical rule, so a route the API adds becomes a
command and a `Client` method with no edit here, and no name is a decision
that could be argued about separately:

* the literal path segments after ``/v1`` become the command words, without a
  ``.json`` suffix;
* a sub-resource of a parameterized route takes its own last segment as the
  command, because the API already says whether it is plural;
* otherwise a route ending in path parameters takes the verb ``get``;
* otherwise a paged collection takes the verb ``list``;
* path parameters become one positional, and query parameters other than the
  paging ones become options.

**An operation this client cannot carry out faithfully is refused while the
contract loads**, naming its path, rather than left out. A route that quietly
went missing from the CLI would read as one the API never published.
"""

from __future__ import annotations

import json
import keyword
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from functools import lru_cache
from importlib import resources
from typing import Any, Final, Literal

#: Where the pinned copy of the contract lives inside the package.
#:
#: Vendored by default rather than fetched. ``/v1/apis/openapi.json`` requires
#: an API key, so a client that fetched it could not list its own commands, or
#: show help, before being configured, and every invocation would spend a
#: request. The copy is kept current by
#: ``.github/workflows/refresh-api-contract.yml``, which releases a patch version
#: whenever the published contract changes. Fetching is the opt-in
#: (`live_contract.py`), for a credential whose tenant has routes not yet
#: released to every tenant.
CONTRACT_PACKAGE: Final[str] = "tmxcaliber.lib.remote.openapi"
CONTRACT_FILE: Final[str] = "v1.json"

#: Where a contract comes from: the vendored copy, or the API's live definition.
ContractName = Literal["vendored", "live"]

#: Every `ContractName`, in the order the command line offers them.
CONTRACT_NAMES: Final[tuple[ContractName, ...]] = ("vendored", "live")

#: What one credential's discovery answer lists: each path, and the filters on
#: it that the credential's tenant may send.
Unlocked = Mapping[str, frozenset[str]]

#: The API version every route sits under, and the one discovery is read for.
API_VERSION: Final[str] = "v1"

#: Query parameters the client spends on walking pages rather than offering.
PAGING_PARAMETERS: Final[frozenset[str]] = frozenset({"limit", "cursor"})

#: The path parameter pair a ThreatModel reference fills, as ``tmId[@release]``.
REFERENCE_PARAMETERS: Final[tuple[str, str]] = ("provider", "service")

#: The positional a ThreatModel reference arrives in.
REFERENCE_POSITIONAL: Final[str] = "tm_id"

#: The option an ``@release`` suffix on a ThreatModel reference stands for.
RELEASE_OPTION: Final[str] = "release"

#: Keywords both surfaces add beside a route's own arguments, so no route
#: argument may take one: ``limit`` sizes a page walk, and
#: ``allow_incomplete`` accepts a partial answer.
RESERVED_ARGUMENTS: Final[frozenset[str]] = frozenset({"limit", "allow_incomplete"})

#: The mark on an operation or parameter not every tenant has yet.
#:
#: The document is the same for every reader, so the API lists what it is
#: releasing to tenants in turn and answers it only for those that have it.
#: A marked route or option is interpreted, so a fault in it still fails the
#: load, and then left out until the mark goes, rather than offered to every
#: caller as a command that answers 404 for most of them. Under the live
#: contract it is also bound once the credential's own discovery answer lists
#: it, which is the API saying this tenant has it.
LIMITED_AVAILABILITY: Final[str] = "x-limited-availability"

#: The one media type the client reads as JSON; any other 200 is bytes.
_JSON_MEDIA_TYPE: Final[str] = "application/json"

#: The keys of an OpenAPI path item that name an HTTP operation.
_METHODS: Final[frozenset[str]] = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

#: What each supported query parameter type is parsed as.
_OPTION_TYPES: Final[dict[str, type[str] | type[int]]] = {"string": str, "integer": int}

#: The schema every paged response extends.
_PAGE_SCHEMA: Final[str] = "#/components/schemas/Page"

#: A response-format suffix on a path segment, which names no command.
_FORMAT_SUFFIX: Final[str] = ".json"

#: A command word: usable unchanged on the command line and as an attribute.
_WORD: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*")

_PLACEHOLDER: Final[re.Pattern[str]] = re.compile(r"\{([^{}]+)\}")


class UnsupportedOperation(ValueError):
    """An operation the contract publishes that this client cannot carry out."""


@dataclass(frozen=True)
class Option:
    """One query parameter a route takes, as the contract declares it.

    Attributes:
        name: The parameter, as the API spells it.
        required: Whether the route refuses to answer without it.
        kind: The type a value is parsed as.
        choices: The values the contract allows; empty when it allows any.
        description: The contract's own description, or empty.
        default: What the API applies when the option is not sent, or None.
            Never sent by the client; it is the API's to apply.
        repeatable: Whether it takes several values, each sent as its own
            ``name=value``; `kind` and `choices` then apply to each value.
    """

    name: str
    required: bool
    kind: type[str] | type[int]
    choices: tuple[str | int, ...]
    description: str
    default: str | int | None = None
    repeatable: bool = False


@dataclass(frozen=True)
class Route:
    """One API route, and the command that reaches it.

    Attributes:
        path: The OpenAPI path template.
        command: The argv words that select it, after the program name.
        paged: Whether the response is a page envelope this client walks.
        options: Query parameters other than ``limit`` and ``cursor``.
        path_parameters: The path template's parameters, in order.
        positional: What the command's positional argument holds, if any.
        summary: One line, for the command's help.
        media_type: The one media type its 200 is served as.
        page_default: The page a paged route serves when no ``limit`` is sent,
            or None when the contract states none.
        page_maximum: The largest page a paged route permits, or None.
        page_fields: Each field its every page must carry beyond the paging
            ones, with the Python types its value may have.

    The media type, the page bounds and the page fields are read from the
    document the route came from and carried here, so a route bound from the
    live definition is executed by what that definition says, never by the
    vendored copy.
    """

    path: str
    command: tuple[str, ...]
    paged: bool
    options: tuple[Option, ...]
    path_parameters: tuple[str, ...]
    positional: str | None
    summary: str
    media_type: str = _JSON_MEDIA_TYPE
    page_default: int | None = None
    page_maximum: int | None = None
    page_fields: tuple[tuple[str, tuple[type, ...]], ...] = ()

    @property
    def binary(self) -> bool:
        """Tell whether the response is bytes rather than JSON, such as a pack archive.

        Returns:
            True when the 200 is served as anything but JSON.
        """
        return self.media_type != _JSON_MEDIA_TYPE

    @property
    def filters(self) -> tuple[str, ...]:
        """Name the route's options as the API spells them.

        Returns:
            The query parameter names, in contract order.
        """
        return tuple(option.name for option in self.options)


#: Routes the client deliberately does not bind.
#:
#: Empty, and it should stay that way. An entry here is a published route a
#: caller cannot reach through this tool, so each one needs a reason and the
#: list may only ever shrink.
UNBOUND: Final[frozenset[str]] = frozenset()


@dataclass(frozen=True, eq=False)
class Contract:
    """The routes one OpenAPI document binds, and the lookups across them.

    Held by whatever builds a surface from it, the command line or one
    `Client`, so two clients built from different documents in one process
    never see each other's routes.

    Attributes:
        routes: Every route bound, in the document's order.
        source: Where the document came from.
    """

    routes: tuple[Route, ...]
    source: ContractName = "vendored"

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
        *,
        unlocked: Unlocked | None = None,
        source: ContractName = "vendored",
    ) -> Contract:
        """Interpret a document into the routes it binds.

        Args:
            document: A parsed OpenAPI document.
            unlocked: What one credential's discovery lists, which binds the
                marked routes and filters it names; None binds none of them.
            source: Where the document came from.

        Returns:
            The contract.

        Raises:
            UnsupportedOperation: As `interpret` does.
        """
        return cls(interpret(document, unlocked=unlocked), source)

    @property
    def live(self) -> bool:
        """Tell whether the document is the API's live definition.

        Returns:
            True when it was read from the API rather than the package.
        """
        return self.source == "live"

    def route_for(self, command: tuple[str, ...]) -> Route | None:
        """Find the route a command reaches.

        Args:
            command: The argv words after the program name.

        Returns:
            The route, or None when no command matches.
        """
        return next((route for route in self.routes if route.command == command), None)

    def route_for_path(self, path: str) -> Route | None:
        """Find the route bound to a path template.

        Args:
            path: The OpenAPI path template.

        Returns:
            The route, or None when no route binds that path.
        """
        return next((route for route in self.routes if route.path == path), None)

    def values_route(self, route: Route, filter_name: str) -> Route | None:
        """Find the route that lists the values one of a route's filters accepts.

        Derived by the same kind of mechanical rule as the command names: the
        paged sibling collection named for the filter's plural. ``frameworkId``
        on ``/v1/compliance/mappings`` is answered by
        ``/v1/compliance/frameworks``, whose rows carry a ``frameworkId``.

        Args:
            route: The route whose filter is being described.
            filter_name: The query parameter, as the API spells it.

        Returns:
            The listing route, or None when this contract binds no such list.
        """
        parent = route.path.rsplit("/", 1)[0]
        noun = filter_name.removesuffix("Id")
        candidate = self.route_for_path(f"{parent}/{noun}s")
        if candidate is None or not candidate.paged or candidate is route:
            return None
        return candidate

    def listing_route(self, route: Route) -> Route | None:
        """Find the collection whose rows name what a route's positional takes.

        The paged route at the path before the first parameter: the ThreatModel
        in ``/v1/threatmodels/{provider}/{service}/threats`` is one that
        ``/v1/threatmodels`` lists.

        Args:
            route: The route whose positional is being described.

        Returns:
            The listing route, or None when the route takes no positional or
            this contract binds no such list.
        """
        if not route.path_parameters:
            return None
        candidate = self.route_for_path(route.path.split("/{", 1)[0])
        if candidate is None or not candidate.paged:
            return None
        return candidate


@lru_cache(maxsize=1)
def contract() -> dict[str, Any]:
    """Load the vendored OpenAPI document.

    Returns:
        The parsed contract.
    """
    text = resources.files(CONTRACT_PACKAGE).joinpath(CONTRACT_FILE).read_text()
    loaded: dict[str, Any] = json.loads(text)
    return loaded


@lru_cache(maxsize=1)
def vendored() -> Contract:
    """Interpret the vendored contract, once per process.

    Returns:
        The contract every tenant is offered.
    """
    return Contract.from_document(contract())


def routes() -> tuple[Route, ...]:
    """List the routes the vendored contract binds.

    Returns:
        Every route the client binds by default, in the contract's order.
    """
    return vendored().routes


def interpret(
    document: Mapping[str, Any], *, unlocked: Unlocked | None = None
) -> tuple[Route, ...]:
    """Read every operation in a contract as the command that reaches it.

    Args:
        document: A parsed OpenAPI document.
        unlocked: What one credential's discovery lists. A marked route binds
            when its path is listed, and a marked filter when it is also among
            that path's filters. None, or a path not listed, binds no marked
            route or filter.

    Returns:
        One route per path outside `UNBOUND` whose operation is not marked
        `LIMITED_AVAILABILITY` or is listed, in the document's order.

    Raises:
        UnsupportedOperation: If an operation cannot be carried out
            faithfully, or two operations would answer to one command. A
            marked operation is held to both whether or not it is listed, so
            it binds as it is once the mark goes.
    """
    listed: Unlocked = unlocked or {}
    items = [
        (path, item)
        for path, item in document.get("paths", {}).items()
        if path not in UNBOUND
    ]
    bound = tuple(
        _route(document, path, item, listed.get(path, frozenset()))
        for path, item in items
    )
    _refuse_collisions(bound)
    waiting = {
        path
        for path, item in items
        if _limited(item.get("get", {})) and path not in listed
    }
    return tuple(route for route in bound if route.path not in waiting)


def _limited(obj: Mapping[str, Any]) -> bool:
    """Tell whether an operation or parameter is marked `LIMITED_AVAILABILITY`.

    Args:
        obj: The operation or parameter object.

    Returns:
        True when the mark is present and true.
    """
    return obj.get(LIMITED_AVAILABILITY) is True


def command_for(path: str, *, paged: bool) -> tuple[str, ...]:
    """Name the command that reaches a path, by the rule in the module docstring.

    Args:
        path: The OpenAPI path template.
        paged: Whether the route's response is a page.

    Returns:
        The argv words, after the program name.

    Raises:
        UnsupportedOperation: If the path is outside ``/v1``, has no literal
            segment, or has one that cannot be a command word.
    """
    version, *tail = path.strip("/").split("/")
    if version != API_VERSION or not tail:
        raise UnsupportedOperation(f"{path}: every route must sit under /v1/.")
    parameterized = [_PLACEHOLDER.fullmatch(segment) is not None for segment in tail]
    literals = tuple(
        segment.removesuffix(_FORMAT_SUFFIX)
        for segment, is_parameter in zip(tail, parameterized, strict=True)
        if not is_parameter
    )
    for word in literals:
        if _WORD.fullmatch(word) is None or keyword.iskeyword(word):
            raise UnsupportedOperation(
                f"{path}: {word!r} cannot be both a command word and a Python "
                "attribute; command words are lowercase letters and digits."
            )
    if not literals:
        raise UnsupportedOperation(f"{path}: has no literal segment to name it by.")
    if parameterized[-1]:
        return (*literals, "get")
    if any(parameterized):
        return literals
    if paged:
        return (*literals, "list")
    return literals


def _route(
    document: Mapping[str, Any],
    path: str,
    item: Mapping[str, Any],
    unlocked_filters: frozenset[str] = frozenset(),
) -> Route:
    """Interpret one path item.

    Args:
        document: The whole contract, for resolving references.
        path: The path template.
        item: Its path item.
        unlocked_filters: Marked filters a credential's discovery lists for
            this path, which bind as any other filter does.

    Returns:
        The route.

    Raises:
        UnsupportedOperation: If the operation cannot be carried out faithfully.
    """
    methods = sorted(_METHODS & set(item))
    if methods != ["get"]:
        declared = ", ".join(method.upper() for method in methods) or "no operation"
        raise UnsupportedOperation(
            f"{path}: declares {declared}; only a lone GET is supported. The API "
            "is read-only today, so executing anything else needs a product "
            "decision first."
        )
    operation: Mapping[str, Any] = item["get"]
    if "requestBody" in operation:
        raise UnsupportedOperation(
            f"{path}: a GET with a request body is not supported."
        )
    summary = " ".join(str(operation.get("summary", "")).split())
    if not summary:
        raise UnsupportedOperation(
            f"{path}: has no summary, which is its command's help."
        )
    media_types = list(_success(operation).get("content", {}))
    if len(media_types) != 1:
        raise UnsupportedOperation(
            f"{path}: its 200 response declares {media_types or 'no content'}; the "
            "client reads exactly one media type."
        )
    # Anything but JSON is bytes the command writes to a file, as a pack
    # archive is; `call_route` holds the answer to the declared type.
    media_type = str(media_types[0])
    parameters = _parameters(document, path, item, operation)
    paged = _is_paged(operation)
    _check_paging(path, paged, parameters)
    if (
        not paged
        and media_type == _JSON_MEDIA_TYPE
        and not _answers_object(document, path, operation)
    ):
        raise UnsupportedOperation(
            f"{path}: its 200 response is not a JSON object, which is the only "
            "answer the client reads outside a page."
        )
    path_parameters = _path_parameters(path, parameters)
    for parameter in parameters:
        # Only an option the route answers without can wait for the mark to go.
        if _limited(parameter) and (
            parameter["in"] != "query"
            or parameter.get("required") is True
            or parameter["name"] in PAGING_PARAMETERS
        ):
            raise UnsupportedOperation(
                f"{path}: the parameter {parameter['name']!r} is marked "
                f"{LIMITED_AVAILABILITY}, but the route cannot be called without it."
            )
    queried = [
        parameter
        for parameter in parameters
        if parameter["in"] == "query" and parameter["name"] not in PAGING_PARAMETERS
    ]
    route = Route(
        path=path,
        command=command_for(path, paged=paged),
        paged=paged,
        options=tuple(_option(document, path, parameter) for parameter in queried),
        path_parameters=path_parameters,
        positional=_positional(path, path_parameters),
        summary=summary,
        media_type=media_type,
        page_default=_page_bound(operation, "default") if paged else None,
        page_maximum=_page_maximum(operation) if paged else None,
        page_fields=tuple(_page_fields(document, operation).items()),
    )
    # Held to the naming rules with every option, marked or not, so a marked
    # one binds as it is once the mark goes.
    _refuse_clashing_names(route)
    return replace(
        route,
        options=tuple(
            option
            for option, parameter in zip(route.options, queried, strict=True)
            if not _limited(parameter) or option.name in unlocked_filters
        ),
    )


def _success(operation: Mapping[str, Any]) -> Mapping[str, Any]:
    """Find an operation's 200 response.

    Args:
        operation: The operation object.

    Returns:
        The response object, or an empty mapping when none is declared.
    """
    response: Mapping[str, Any] = operation.get("responses", {}).get("200", {})
    return response


def _answers_object(
    document: Mapping[str, Any], path: str, operation: Mapping[str, Any]
) -> bool:
    """Tell whether an operation's JSON answer is declared an object.

    The client refuses any other body as a contract violation, so a route
    answering an array or a scalar outside a page would be a command that
    could never succeed.

    Args:
        document: The whole contract, for a referenced schema.
        path: The path template, for the message.
        operation: The operation object.

    Returns:
        True when the 200 schema, references followed, is ``type: object``.
    """
    content = _success(operation).get("content", {})
    schema = _resolve(
        document, path, content.get("application/json", {}).get("schema", {})
    )
    return schema.get("type") == "object"


def _is_paged(operation: Mapping[str, Any]) -> bool:
    """Tell whether an operation answers with a page envelope.

    Args:
        operation: The operation object.

    Returns:
        True when its 200 schema extends the contract's ``Page``.
    """
    content = _success(operation).get("content", {})
    schema = content.get("application/json", {}).get("schema", {})
    return any(part.get("$ref") == _PAGE_SCHEMA for part in schema.get("allOf", []))


def _resolve(
    document: Mapping[str, Any], path: str, node: Mapping[str, Any]
) -> dict[str, Any]:
    """Follow a local ``$ref`` to what it names.

    Args:
        document: The whole contract.
        path: The path template, for the message.
        node: An object that may be a reference.

    Returns:
        The referenced object, or a copy of the node when it is not one.

    Raises:
        UnsupportedOperation: If the reference is not local or names nothing.
    """
    reference = node.get("$ref")
    if reference is None:
        return dict(node)
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise UnsupportedOperation(
            f"{path}: only local references are supported, not {reference!r}."
        )
    target: Any = document
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, Mapping) or part not in target:
            raise UnsupportedOperation(f"{path}: {reference} names nothing.")
        target = target[part]
    return _resolve(document, path, target)


def _parameters(
    document: Mapping[str, Any],
    path: str,
    item: Mapping[str, Any],
    operation: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Merge path-level and operation-level parameters, resolving references.

    Args:
        document: The whole contract.
        path: The path template.
        item: The path item.
        operation: The operation object.

    Returns:
        Each parameter once, the operation's declaration winning as OpenAPI
        specifies.

    Raises:
        UnsupportedOperation: If a parameter is neither a path nor a query one.
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for declared in (*item.get("parameters", []), *operation.get("parameters", [])):
        parameter = _resolve(document, path, declared)
        location = parameter.get("in")
        if location not in ("path", "query"):
            raise UnsupportedOperation(
                f"{path}: the {location} parameter {parameter.get('name')!r} is not "
                "supported; only path and query parameters are."
            )
        merged[(location, str(parameter["name"]))] = parameter
    return list(merged.values())


def _check_paging(path: str, paged: bool, parameters: list[dict[str, Any]]) -> None:
    """Refuse a route whose paging parameters disagree with its response.

    Args:
        path: The path template.
        paged: Whether the response is a page.
        parameters: The merged parameters.

    Raises:
        UnsupportedOperation: If a page cannot be walked, or a route that is
            not paged takes paging parameters the client would drop.
    """
    names = {str(p["name"]) for p in parameters if p["in"] == "query"}
    if paged and not names >= PAGING_PARAMETERS:
        raise UnsupportedOperation(
            f"{path}: answers with a page but does not take both limit and cursor, "
            "so the client could not walk it."
        )
    if not paged and names & PAGING_PARAMETERS:
        raise UnsupportedOperation(
            f"{path}: takes {', '.join(sorted(names & PAGING_PARAMETERS))} but its "
            "response is not a page, so the client could not tell when to stop."
        )


def _path_parameters(path: str, parameters: list[dict[str, Any]]) -> tuple[str, ...]:
    """Read a path's parameters, held to what the operation declares.

    Args:
        path: The path template.
        parameters: The merged parameters.

    Returns:
        The template's parameter names, in order.

    Raises:
        UnsupportedOperation: If the template and the declarations disagree.
    """
    placeholders = tuple(_PLACEHOLDER.findall(path))
    declared = sorted(str(p["name"]) for p in parameters if p["in"] == "path")
    if sorted(placeholders) != declared:
        raise UnsupportedOperation(
            f"{path}: the template names {sorted(placeholders)} but the operation "
            f"declares {declared}."
        )
    return placeholders


def _positional(path: str, names: tuple[str, ...]) -> str | None:
    """Name the positional that fills a route's path parameters.

    Args:
        path: The path template.
        names: Its parameters, in order.

    Returns:
        The positional's name, or None when the path takes none.

    Raises:
        UnsupportedOperation: If one positional cannot fill the parameters.
    """
    if not names:
        return None
    if names == REFERENCE_PARAMETERS:
        return REFERENCE_POSITIONAL
    if len(names) == 1:
        return python_name(names[0])
    raise UnsupportedOperation(
        f"{path}: one positional cannot fill {len(names)} path parameters; only "
        "{provider}/{service}, read as a ThreatModel reference, is supported."
    )


def _option(
    document: Mapping[str, Any], path: str, parameter: Mapping[str, Any]
) -> Option:
    """Interpret one query parameter.

    Args:
        document: The whole contract, for a referenced schema.
        path: The path template, for the message.
        parameter: The parameter object.

    Returns:
        The option.

    Raises:
        UnsupportedOperation: If its type, or for an array each value's type,
            is not one the command line parses, or an array is not sent once
            per value.
    """
    name = str(parameter["name"])
    schema = _resolve(document, path, parameter.get("schema", {}))
    repeatable = schema.get("type") == "array"
    if repeatable:
        # An array in a query is sent once per value unless the contract says
        # otherwise (`style: form`, `explode: true` are OpenAPI's defaults),
        # which is the only spelling the API reads as any of several values.
        if (
            parameter.get("style", "form") != "form"
            or parameter.get("explode", True) is not True
        ):
            raise UnsupportedOperation(
                f"{path}: the query parameter {name!r} is an array not sent once "
                "per value; only `style: form` with `explode: true` is supported."
            )
        # A default would be stated in the help, and a list of them has no
        # spelling there that a caller could not misread as one value.
        if "default" in schema:
            raise UnsupportedOperation(
                f"{path}: the query parameter {name!r} is an array with a default, "
                "which is not supported."
            )
        schema = _resolve(document, path, schema.get("items", {}))
    declared = schema.get("type", "string")
    kind = _OPTION_TYPES.get(declared) if isinstance(declared, str) else None
    if kind is None:
        values = "values of " if repeatable else ""
        raise UnsupportedOperation(
            f"{path}: the query parameter {name!r} has {values}type {declared!r}; "
            f"only {', '.join(_OPTION_TYPES)} are supported."
        )
    return Option(
        name=name,
        required=parameter.get("required") is True,
        kind=kind,
        choices=tuple(kind(value) for value in schema.get("enum", ())),
        description=" ".join(str(parameter.get("description", "")).split()),
        default=None if schema.get("default") is None else kind(schema["default"]),
        repeatable=repeatable,
    )


def _refuse_clashing_names(route: Route) -> None:
    """Refuse a route whose arguments would share a Python name.

    Args:
        route: The route.

    Raises:
        UnsupportedOperation: If two options, or an option and the positional,
            spell the same keyword, or one cannot be a keyword at all.
    """
    names = [python_name(option.name) for option in route.options]
    if route.positional:
        names.append(route.positional)
    for name in names:
        if not name.isidentifier() or keyword.iskeyword(name):
            raise UnsupportedOperation(f"{route.path}: {name!r} cannot be a keyword.")
        if name in RESERVED_ARGUMENTS:
            raise UnsupportedOperation(
                f"{route.path}: {name!r} is an argument the client adds itself."
            )
    if len(names) != len(set(names)):
        raise UnsupportedOperation(
            f"{route.path}: two arguments would share one Python name among {names}."
        )


def _refuse_collisions(bound: tuple[Route, ...]) -> None:
    """Refuse two routes on one command, or one command that is also a group.

    Args:
        bound: Every interpreted route.

    Raises:
        UnsupportedOperation: On the first collision found.
    """
    seen: dict[tuple[str, ...], str] = {}
    for route in bound:
        if route.command in seen:
            raise UnsupportedOperation(
                f"{route.path} and {seen[route.command]} both answer to "
                f"`{' '.join(route.command)}`."
            )
        seen[route.command] = route.path
    for command, path in seen.items():
        for depth in range(1, len(command)):
            prefix = command[:depth]
            if prefix in seen:
                raise UnsupportedOperation(
                    f"`{' '.join(prefix)}` would be both a command ({seen[prefix]}) "
                    f"and a group ({path})."
                )


def available_paths() -> frozenset[str]:
    """List the paths the vendored contract offers every tenant.

    A path whose operation is marked `LIMITED_AVAILABILITY` is left out, as
    `interpret` leaves it out of the commands.

    Returns:
        The path templates.
    """
    return frozenset(
        path
        for path, item in contract()["paths"].items()
        if not _limited(item.get("get", {}))
    )


def row_properties(path: str) -> dict[str, Any]:
    """Read a collection's row properties from the vendored contract.

    Args:
        path: The route's OpenAPI path template.

    Returns:
        The live row's property schemas, including canonical key metadata.
    """
    response = contract()["paths"][path]["get"]["responses"]["200"]
    schema = response["content"]["application/json"]["schema"]
    member = next(part for part in schema["allOf"] if "properties" in part)
    reference = member["properties"]["items"]["items"]["$ref"]
    row = contract()["components"]["schemas"][reference.rsplit("/", 1)[-1]]
    live = row["oneOf"][0] if "oneOf" in row else row
    properties: dict[str, Any] = live["properties"]
    return properties


def route_for(command: tuple[str, ...]) -> Route | None:
    """Find the route a command reaches in the vendored contract.

    Args:
        command: The argv words after the program name.

    Returns:
        The route, or None when no command matches.
    """
    return vendored().route_for(command)


def _operation(document: Mapping[str, Any], path: str) -> Mapping[str, Any]:
    """Find a path's GET operation in a document.

    Args:
        document: A parsed OpenAPI document.
        path: The OpenAPI path template.

    Returns:
        The operation object, or an empty mapping when the path declares none.
    """
    found: Mapping[str, Any] = document["paths"].get(path, {}).get("get", {})
    return found


def _page_bound(operation: Mapping[str, Any], keyword: str) -> int | None:
    """Read one bound of an operation's ``limit`` from its schema.

    Args:
        operation: The operation object.
        keyword: ``default``, the page served when no limit is sent, or
            ``maximum``, the largest page permitted.

    Returns:
        The bound, or None when the operation takes no ``limit`` or its schema
        states no such bound.
    """
    for parameter in operation.get("parameters", []):
        if parameter.get("name") == "limit":
            bound = parameter.get("schema", {}).get(keyword)
            return int(bound) if bound is not None else None
    return None


def _page_maximum(operation: Mapping[str, Any]) -> int | None:
    """Read an operation's largest permitted page size.

    Walking a collection at its maximum is what keeps a full read inside the
    API's hourly budget, and the maximum is the contract's to state.

    Args:
        operation: The operation object.

    Returns:
        The maximum, or None when the operation takes no ``limit`` or states
        no maximum for it.
    """
    return _page_bound(operation, "maximum")


def page_maximum(path: str) -> int | None:
    """Read a route's largest permitted page size from the vendored contract.

    Args:
        path: The OpenAPI path template.

    Returns:
        The maximum, or None when the route is not paged.
    """
    return _page_maximum(_operation(contract(), path))


def response_media_type(path: str) -> str | None:
    """Name the media type a route's 200 is served as, in the vendored contract.

    Read from the contract, because whether a route answers with JSON or with
    bytes is the API's decision, and a client that guessed would decode a zip.

    Args:
        path: The OpenAPI path template.

    Returns:
        The media type, or None when the contract declares no 200 content.
    """
    return next(iter(_success(_operation(contract(), path)).get("content", {})), None)


def values_field(filter_name: str) -> str:
    """Name the row field of a values route that a filter takes.

    Args:
        filter_name: The query parameter, as the API spells it.

    Returns:
        The field, in the API's camelCase.
    """
    return filter_name if filter_name.endswith("Id") else f"{filter_name}Id"


def python_name(api_name: str) -> str:
    """Spell an API parameter as a Python keyword or argparse destination.

    Args:
        api_name: The camelCase query parameter from OpenAPI.

    Returns:
        Its snake_case spelling.
    """
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", api_name).lower()


def route_for_path(path: str) -> Route | None:
    """Find the route bound to a path template in the vendored contract.

    Args:
        path: The OpenAPI path template.

    Returns:
        The route, or None when no route binds that path.
    """
    return vendored().route_for_path(path)


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


def _paging_fields(document: Mapping[str, Any]) -> frozenset[str]:
    """List the fields every page carries, as a document's ``Page`` declares.

    Args:
        document: A parsed OpenAPI document.

    Returns:
        The envelope fields the client walks by, such as ``nextCursor``.
    """
    return frozenset(document["components"]["schemas"]["Page"]["required"])


def paging_fields() -> frozenset[str]:
    """List the fields every page carries, as the vendored ``Page`` declares.

    Returns:
        The envelope fields the client walks by, such as ``nextCursor``.
    """
    return _paging_fields(contract())


def required_page_fields(path: str) -> dict[str, tuple[type, ...]]:
    """List the fields a route's every page must carry, in the vendored contract.

    Args:
        path: The OpenAPI path template.

    Returns:
        Each required field and the Python types its value may have; empty
        for a route that is not paged or declares none.
    """
    return _page_fields(contract(), _operation(contract(), path))


def _page_fields(
    document: Mapping[str, Any], operation: Mapping[str, Any]
) -> dict[str, tuple[type, ...]]:
    """List the fields an operation's every page must carry beyond the paging ones.

    Read from the contract's 200 schema, so a field the API makes required,
    such as which ThreatModels a compliance mapping could not resolve, is held
    to without restating it here. A page that omits one is a contract breach,
    not an answer with nothing to report.

    Args:
        document: The document the operation belongs to, for its ``Page``.
        operation: The operation object.

    Returns:
        Each required field and the Python types its value may have; empty
        for an operation that is not paged or declares none.
    """
    schema = (
        _success(operation)
        .get("content", {})
        .get(_JSON_MEDIA_TYPE, {})
        .get("schema", {})
    )
    fields: dict[str, tuple[type, ...]] = {}
    for part in schema.get("allOf", []):
        properties = part.get("properties", {})
        for name in part.get("required", []):
            if name in _paging_fields(document):
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


def query_parameter(path: str, name: str) -> dict[str, Any]:
    """Read one query parameter as the contract declares it.

    What an option means, which values it takes and what it defaults to are
    the API's to say, so the command line prints the parameter's own
    description and offers its enum rather than restating either.

    Args:
        path: The OpenAPI path template.
        name: The parameter, as the API spells it.

    Returns:
        The parameter object, with its ``description`` and ``schema``; empty
        when the route declares no such query parameter.
    """
    for parameter in (
        contract()["paths"].get(path, {}).get("get", {}).get("parameters", [])
    ):
        if parameter.get("in") == "query" and parameter.get("name") == name:
            declared: dict[str, Any] = parameter
            return declared
    return {}


def available_query_parameters(path: str) -> frozenset[str]:
    """List a route's query parameters that the contract offers every tenant.

    A parameter marked `LIMITED_AVAILABILITY` is left out, as `interpret`
    leaves it out of the route's options.

    Args:
        path: The OpenAPI path template.

    Returns:
        Every unmarked query parameter name, including ``limit`` and ``cursor``.
    """
    names = {
        str(parameter["name"])
        for parameter in contract()["paths"]
        .get(path, {})
        .get("get", {})
        .get("parameters", [])
        if parameter.get("in") == "query" and not _limited(parameter)
    }
    return frozenset(names)

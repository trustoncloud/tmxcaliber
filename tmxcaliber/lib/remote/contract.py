"""The API's operations, interpreted from the vendored OpenAPI contract.

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
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Final

#: Where the pinned copy of the contract lives inside the package.
#:
#: Vendored rather than fetched. ``/v1/apis/openapi.json`` sits behind
#: authentication and the tenant's IP policy, so a client cannot read the
#: contract it is about to call without already being configured for it, from
#: an address that tenant admits.
CONTRACT_PACKAGE: Final[str] = "tmxcaliber.lib.remote.openapi"
CONTRACT_FILE: Final[str] = "v1.json"

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

#: The keys of an OpenAPI path item that name an HTTP operation.
_METHODS: Final[frozenset[str]] = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

#: What each supported query parameter type is parsed as.
_OPTION_TYPES: Final[dict[str, type[str] | type[int]]] = {"string": str, "integer": int}

#: The schema every paged response extends.
_PAGE_SCHEMA: Final[str] = "#/components/schemas/Page"

#: The path segment every route starts with, which names no command.
_VERSION_SEGMENT: Final[str] = "v1"

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
    """

    name: str
    required: bool
    kind: type[str] | type[int]
    choices: tuple[str | int, ...]
    description: str


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
    """

    path: str
    command: tuple[str, ...]
    paged: bool
    options: tuple[Option, ...]
    path_parameters: tuple[str, ...]
    positional: str | None
    summary: str

    @property
    def filters(self) -> tuple[str, ...]:
        """Name the route's options as the API spells them.

        Returns:
            The query parameter names, in contract order.
        """
        return tuple(option.name for option in self.options)


#: Routes the client deliberately does not bind.
#:
#: The archive is binary; this client only handles JSON responses. Naming the
#: omission keeps every other non-JSON route a load failure rather than a
#: command that silently never appears.
UNBOUND: Final[frozenset[str]] = frozenset({"/v1/ccr/packs/{tmId}/archive"})


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
def routes() -> tuple[Route, ...]:
    """Interpret the vendored contract, once per process.

    Returns:
        Every route the client binds, in the contract's order.
    """
    return interpret(contract())


def interpret(document: Mapping[str, Any]) -> tuple[Route, ...]:
    """Read every operation in a contract as the command that reaches it.

    Args:
        document: A parsed OpenAPI document.

    Returns:
        One route per path outside `UNBOUND`, in the document's order.

    Raises:
        UnsupportedOperation: If an operation cannot be carried out
            faithfully, or two operations would answer to one command.
    """
    bound = tuple(
        _route(document, path, item)
        for path, item in document.get("paths", {}).items()
        if path not in UNBOUND
    )
    _refuse_collisions(bound)
    return bound


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
    if version != _VERSION_SEGMENT or not tail:
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


def _route(document: Mapping[str, Any], path: str, item: Mapping[str, Any]) -> Route:
    """Interpret one path item.

    Args:
        document: The whole contract, for resolving references.
        path: The path template.
        item: Its path item.

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
    if "application/json" not in _success(operation).get("content", {}):
        raise UnsupportedOperation(
            f"{path}: its 200 response is not JSON. Teach the client the response, "
            "or name the path in UNBOUND with the reason."
        )
    parameters = _parameters(document, path, item, operation)
    paged = _is_paged(operation)
    _check_paging(path, paged, parameters)
    if not paged and not _answers_object(document, path, operation):
        raise UnsupportedOperation(
            f"{path}: its 200 response is not a JSON object, which is the only "
            "answer the client reads outside a page."
        )
    path_parameters = _path_parameters(path, parameters)
    route = Route(
        path=path,
        command=command_for(path, paged=paged),
        paged=paged,
        options=tuple(
            _option(document, path, parameter)
            for parameter in parameters
            if parameter["in"] == "query" and parameter["name"] not in PAGING_PARAMETERS
        ),
        path_parameters=path_parameters,
        positional=_positional(path, path_parameters),
        summary=summary,
    )
    _refuse_clashing_names(route)
    return route


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
        UnsupportedOperation: If its type is not one the command line parses.
    """
    name = str(parameter["name"])
    schema = _resolve(document, path, parameter.get("schema", {}))
    declared = schema.get("type", "string")
    kind = _OPTION_TYPES.get(declared) if isinstance(declared, str) else None
    if kind is None:
        raise UnsupportedOperation(
            f"{path}: the query parameter {name!r} has type {declared!r}; only "
            f"{', '.join(_OPTION_TYPES)} are supported."
        )
    return Option(
        name=name,
        required=parameter.get("required") is True,
        kind=kind,
        choices=tuple(kind(value) for value in schema.get("enum", ())),
        description=" ".join(str(parameter.get("description", "")).split()),
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


def documented_paths() -> frozenset[str]:
    """List every path the vendored contract publishes.

    Returns:
        The path templates.
    """
    return frozenset(contract()["paths"])


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
    """Find the route a command reaches.

    Args:
        command: The argv words after the program name.

    Returns:
        The route, or None when no command matches.
    """
    for route in routes():
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


def values_route(route: Route, filter_name: str) -> Route | None:
    """Find the route that lists the values one of a route's filters accepts.

    Derived by the same kind of mechanical rule as the command names: the
    paged sibling collection named for the filter's plural. ``frameworkId`` on
    ``/v1/compliance/mappings`` is answered by ``/v1/compliance/frameworks``,
    whose rows carry a ``frameworkId``.

    Args:
        route: The route whose filter is being described.
        filter_name: The query parameter, as the API spells it.

    Returns:
        The listing route, or None when the API publishes no such list.
    """
    parent = route.path.rsplit("/", 1)[0]
    noun = filter_name.removesuffix("Id")
    candidate = route_for_path(f"{parent}/{noun}s")
    if candidate is None or not candidate.paged or candidate is route:
        return None
    return candidate


def listing_route(route: Route) -> Route | None:
    """Find the collection whose rows name what a route's positional takes.

    The paged route at the path before the first parameter: the ThreatModel
    in ``/v1/threatmodels/{provider}/{service}/threats`` is one that
    ``/v1/threatmodels`` lists.

    Args:
        route: The route whose positional is being described.

    Returns:
        The listing route, or None when the route takes no positional or the
        API publishes no such list.
    """
    if not route.path_parameters:
        return None
    candidate = route_for_path(route.path.split("/{", 1)[0])
    if candidate is None or not candidate.paged:
        return None
    return candidate


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
    """Find the route bound to a path template.

    Args:
        path: The OpenAPI path template.

    Returns:
        The route, or None when no route binds that path.
    """
    for route in routes():
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

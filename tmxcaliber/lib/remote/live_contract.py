"""The API's live definition, read for one credential.

The opt-in behind ``--contract live`` (``--live``) and
``Client(contract="live")``. Two calls, both answered from any address:

1. ``/v1/apis``, which is per credential. It leaves out a route or filter the
   caller's tenant does not have yet, so it is what tells this client which
   routes and filters marked ``x-limited-availability`` it may bind.
2. The definition that answer points at, used **wholesale** in place of the
   vendored copy, so a route the API has published since this release was
   built is a command too.

The served definition is the same for every reader, which is why it alone
cannot say what this credential has; discovery is the only per-tenant answer.

**The two are joined on ``operationId``**, which both publish for every
operation. Their paths do not agree in spelling: discovery writes a template
Express's way, ``/v1/overwatch/updates/:overwatchId``, where the definition
writes ``{overwatchId}``, so matching on the path silently unlocked no
parameterized route at all.

Nothing is cached: every live contract costs both calls, against the same
hourly budget as the command that follows.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import Any, Final

from .client import TocClient
from .contract import API_VERSION, Contract, UnsupportedOperation, route_for_path
from .errors import ContractViolation, RemoteError
from .operations import call_route

#: The route that lists each API definition and what this credential may call.
DISCOVERY_PATH: Final[str] = "/v1/apis"

#: The ``name`` of this API's row in that list; ``version`` is `API_VERSION`.
DEFINITION_NAME: Final[str] = "trustoncloud"

#: How a caller goes back to the contract this release ships with.
_REMEDY: Final[str] = (
    "Use the contract this release ships with (leave out --live and "
    '--contract live; in Python, contract="vendored"), or upgrade tmxcaliber.'
)


def load_live_contract(client: TocClient) -> Contract:
    """Read the API's live definition, with what this credential may bind.

    Args:
        client: The client to read through. Its endpoint is the only origin
            the definition may be read from.

    Returns:
        The live contract: every route the definition binds, with a route or
        filter marked ``x-limited-availability`` bound only when this
        credential's discovery answer lists it.

    Raises:
        ContractViolation: If discovery or the definition is not in a shape
            this client reads, or the definition holds an operation this
            release cannot carry out.
        RemoteError: If the definition is on another origin, which would
            disclose the API key, or on any transport, credential or server
            failure.
    """
    discovery = route_for_path(DISCOVERY_PATH)
    assert discovery is not None, f"{DISCOVERY_PATH} is not bound"
    rows = call_route(
        client, discovery, "", {}, limit=discovery.page_maximum or 0
    ).result
    row = _definition_row(rows)
    listed = _listed(row.get("operations"))
    path = _definition_path(client.base_url, row.get("definitionUrl"))
    document = client.get(path)
    _check_document(document, path)
    try:
        return Contract.from_document(
            document, unlocked=_unlocked(document, listed), source="live"
        )
    except UnsupportedOperation as exc:
        raise live_refusal(exc) from exc
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        # The interpreter indexes a document it trusts to be OpenAPI. The
        # vendored copy is held to that in CI; a served one is not, and a
        # malformed one must read as the API's fault rather than a traceback.
        raise ContractViolation(
            f"{path} is not a definition this client can read: "
            f"{type(exc).__name__}: {exc}. {_REMEDY}",
            code="bad_definition",
        ) from exc


def live_refusal(exc: Exception) -> ContractViolation:
    """Report a live definition that this release cannot bind.

    The vendored contract is held to every refusal in CI, so the only way to
    meet one at run time is a served definition newer than this release.

    Args:
        exc: The refusal, whose message names the path or command concerned.

    Returns:
        The error to raise, naming the remedies.
    """
    return ContractViolation(
        "The API's live definition holds something this tmxcaliber cannot "
        f"carry out: {exc} {_REMEDY}",
        code="unsupported_operation",
    )


def _drift(detail: str) -> ContractViolation:
    """Report a discovery answer in a shape this client does not read.

    Args:
        detail: What was wrong with it.

    Returns:
        The error to raise.
    """
    return ContractViolation(
        f"{DISCOVERY_PATH} answered in a shape this client does not read: {detail}.",
        code="bad_discovery",
    )


def _definition_row(rows: Any) -> Mapping[str, Any]:
    """Pick this API's v1 definition out of the discovery rows.

    Args:
        rows: Every row discovery returned.

    Returns:
        The one row naming `DEFINITION_NAME` at `API_VERSION`.

    Raises:
        ContractViolation: If no row, or more than one, names it, since
            either way there is no single definition to read.
    """
    if not isinstance(rows, list):
        raise _drift("its rows are not a list")
    matches = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and row.get("name") == DEFINITION_NAME
        and row.get("version") == API_VERSION
    ]
    if len(matches) != 1:
        raise _drift(
            f"it lists {len(matches)} {DEFINITION_NAME} {API_VERSION} definitions "
            "where exactly one was expected"
        )
    return matches[0]


def _listed(operations: object) -> dict[str, frozenset[str]]:
    """Read which operations, and which filters on each, this credential may use.

    The published contract types ``operations`` only as an array, so each
    item is held here to the fields this client reads, and must hold them
    with a usable value rather than one that merely survives coercion.

    **Being listed is the gate; ``allowed`` is deliberately not read.** The
    mark means "not every tenant has this yet", and discovery leaving an
    operation out is the API's answer to exactly that. Whether this key may
    call it is another question, which the vendored contract never asks
    either: a key without a route's permission is still offered the command
    and gets the API's own ``403``. Reading ``allowed`` would also hide every
    marked route from a caller outside the tenant's IP ranges, since
    discovery then allows only itself and the definition, turning the API's
    ``ip_not_allowed`` into a command that does not exist.

    Args:
        operations: The definition row's ``operations``.

    Returns:
        Each listed ``operationId`` and the filters listed for it, merged
        where an operation appears twice.

    Raises:
        ContractViolation: If ``operations`` is not a list of objects, each
            with a non-empty ``operationId`` and a list of non-empty
            ``filters``.
    """
    if not isinstance(operations, list):
        raise _drift("the definition's operations are not a list")
    listed: dict[str, set[str]] = {}
    for position, item in enumerate(operations):
        if not isinstance(item, Mapping):
            raise _drift(f"operation {position} is not an object")
        operation_id = item.get("operationId")
        filters = item.get("filters")
        if not isinstance(operation_id, str) or not operation_id:
            raise _drift(f"operation {position} names no operationId")
        if not isinstance(filters, list) or not all(
            isinstance(name, str) and name for name in filters
        ):
            raise _drift(f"{operation_id} does not list its filters as names")
        listed.setdefault(operation_id, set()).update(filters)
    return {operation_id: frozenset(names) for operation_id, names in listed.items()}


def _unlocked(
    document: Mapping[str, Any], listed: Mapping[str, frozenset[str]]
) -> dict[str, frozenset[str]]:
    """Find the definition's path for each operation discovery lists.

    An operation the definition does not have is ignored: it can only unlock
    what the definition defines, and a definition a moment behind discovery
    is a lag, not a fault.

    Args:
        document: The served definition, already held to `_check_document`.
        listed: What `_listed` read, by ``operationId``.

    Returns:
        Each listed operation's path template, as the definition spells it,
        and the filters listed for it.
    """
    unlocked: dict[str, frozenset[str]] = {}
    for template, item in document["paths"].items():
        # A malformed path item is left for the interpreter to refuse.
        operation = item.get("get") if isinstance(item, Mapping) else None
        if not isinstance(operation, Mapping):
            continue
        filters = listed.get(str(operation.get("operationId", "")))
        if filters is not None:
            unlocked[template] = filters
    return unlocked


def _definition_path(base_url: str, url: object) -> str:
    """Turn the definition's URL into a path on this client's endpoint.

    The key travels in a header, so a definition anywhere but this client's
    own origin is refused before it is asked for, for the same reason a
    redirect off the origin is.

    Args:
        base_url: This client's endpoint.
        url: The definition row's ``definitionUrl``.

    Returns:
        The path to ask the endpoint for.

    Raises:
        ContractViolation: If the URL is missing, not absolute, carries a
            query or fragment, or sits outside the endpoint's base path.
        RemoteError: If it is on another scheme, host or port.
    """
    if not isinstance(url, str) or not url:
        raise _drift("the definition names no definitionUrl")
    here = urllib.parse.urlsplit(base_url)
    there = urllib.parse.urlsplit(url)
    if not there.scheme or not there.netloc:
        raise _drift(f"the definitionUrl {url!r} is not absolute")
    if (there.scheme, there.netloc.lower()) != (here.scheme, here.netloc.lower()):
        raise RemoteError(
            f"{DISCOVERY_PATH} puts the definition at {there.scheme}://"
            f"{there.netloc}, not on {here.scheme}://{here.netloc}, which would "
            "disclose the API key. Refusing to read it.",
            code="cross_origin_definition",
        )
    if there.query or there.fragment:
        raise _drift(f"the definitionUrl {url!r} carries a query or fragment")
    base_path = here.path.rstrip("/")
    if not there.path.startswith(f"{base_path}/"):
        raise _drift(f"the definitionUrl {url!r} is outside {base_url}")
    return there.path[len(base_path) :]


def _check_document(document: Mapping[str, Any], path: str) -> None:
    """Hold the served definition to the shape every contract has.

    Args:
        document: What the definition URL answered.
        path: Where it was read from, for the message.

    Raises:
        ContractViolation: If it is not an OpenAPI 3 document with paths.
    """
    version = document.get("openapi")
    paths = document.get("paths")
    if not isinstance(version, str) or not version.startswith("3."):
        raise ContractViolation(
            f"{path} is not an OpenAPI 3 document. {_REMEDY}", code="bad_definition"
        )
    if not isinstance(paths, Mapping) or not paths:
        raise ContractViolation(
            f"{path} defines no paths. {_REMEDY}", code="bad_definition"
        )

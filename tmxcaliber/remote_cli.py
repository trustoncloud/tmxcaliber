"""The API commands, built from the contract rather than written out.

Every group, command, positional and option below is derived from
`lib/remote/contract.py`, which is itself held against the vendored OpenAPI
document. Adding a route to the API therefore adds a command here with no
naming decision to make and nothing to keep in step by hand.

The shape mirrors the API:

    tmxcaliber me
    tmxcaliber threatmodels list --provider aws
    tmxcaliber threatmodels get aws-s3
    tmxcaliber threatmodels threats aws-s3 --feature-class S3.FC1
    tmxcaliber threatmodels dfd aws-s3@1611187200
    tmxcaliber compliance mappings list --framework "NIST CSF v2.0"
"""

from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from typing import Any

from .lib.remote.client import TocClient
from .lib.remote.config import load_settings
from .lib.remote.contract import ROUTES, Route, required_parameters
from .lib.remote.ref import parse_ref

#: The namespace key each nesting level of the command tree parks its word in.
#:
#: `operation` is the top level, which the existing commands already use.
LEVEL_DEST = "api_level_{depth}"

#: What a positional holds, and how its help reads.
POSITIONALS = {
    "tm_id": (
        "TMID",
        "the ThreatModel, as `threatmodels list` reports it, "
        "optionally pinned with @release (for example aws-s3@1611187200).",
    ),
    "release_key": ("RELEASEKEY", "the pack's release key."),
}


def _option(filter_name: str) -> str:
    """Render a query parameter as its command-line option.

    Args:
        filter_name: The parameter name as the API spells it.

    Returns:
        The option, with underscores turned into dashes.
    """
    return f"--{filter_name.replace('_', '-')}"


def _leaf(parser: ArgumentParser, route: Route) -> None:
    """Add one route's arguments to its parser.

    Args:
        parser: The parser for this command.
        route: The route it reaches.
    """
    if route.positional:
        metavar, help_text = POSITIONALS[route.positional]
        parser.add_argument(route.positional, metavar=metavar, help=help_text)
    required = required_parameters(route.path)
    for name in route.filters:
        parser.add_argument(
            _option(name),
            dest=name,
            default="",
            required=name in required,
            help=f"filter by {name.replace('_', ' ')}.",
        )
    if route.paged:
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help=(
                "rows per request. The whole collection is read either way; "
                "this only changes how many calls that takes."
            ),
        )
    parser.add_argument(
        "--output",
        default="",
        help="file to write the result to. Prints to stdout when omitted.",
    )
    parser.set_defaults(api_route=route)


def add_api_parsers(subparsers: _SubParsersAction[ArgumentParser]) -> None:
    """Build every API command onto the top-level parser.

    Args:
        subparsers: The top-level subparser action.
    """
    # One parser per group prefix, created on first use so the tree is built
    # from the route table rather than spelled out.
    groups: dict[tuple[str, ...], _SubParsersAction[ArgumentParser]] = {}

    for route in ROUTES:
        parent: _SubParsersAction[ArgumentParser] = subparsers
        for depth, word in enumerate(route.command[:-1]):
            prefix = route.command[: depth + 1]
            if prefix not in groups:
                group_parser = parent.add_parser(
                    word, help=f"{word} operations against the TrustOnCloud API."
                )
                groups[prefix] = group_parser.add_subparsers(
                    dest=LEVEL_DEST.format(depth=depth + 1), required=True
                )
            parent = groups[prefix]
        leaf = parent.add_parser(route.command[-1], help=route.summary)
        _leaf(leaf, route)


def selected_route(params: Namespace) -> Route | None:
    """Report which API route a parsed command reaches.

    Args:
        params: The parsed arguments.

    Returns:
        The route, or None when the command is not an API command.
    """
    route = getattr(params, "api_route", None)
    return route if isinstance(route, Route) else None


def _path_for(route: Route, params: Namespace) -> str:
    """Fill a route's path parameters from the parsed command.

    Args:
        route: The route.
        params: The parsed arguments.

    Returns:
        The concrete path.

    Raises:
        ValueError: If a ThreatModel reference cannot be parsed.
    """
    path = route.path
    if route.positional == "tm_id":
        ref = parse_ref(params.tm_id)
        path = path.replace("{provider}", ref.provider).replace(
            "{service}", ref.service
        )
        # `@release` is sugar for the query parameter, so a caller can pin
        # either way and only one of them reaches the wire.
        if ref.release and not getattr(params, "release", ""):
            params.release = ref.release
    elif route.positional == "release_key":
        path = path.replace("{releaseKey}", params.release_key)
    return path


def run_api_command(
    params: Namespace, *, client: TocClient | None = None
) -> tuple[Any, str]:
    """Execute an API command.

    Args:
        params: The parsed arguments.
        client: A client to use, built from the environment when omitted.

    Returns:
        The result and the result type `output_result` expects.

    Raises:
        RemoteError: On any credential, transport or server failure.
        ValueError: If a ThreatModel reference cannot be parsed.
    """
    route = selected_route(params)
    assert route is not None, "run_api_command called for a non-API command"
    api = client or TocClient(load_settings())
    path = _path_for(route, params)
    query = {name: str(getattr(params, name, "") or "") for name in route.filters}

    if route.paged:
        rows = list(
            api.paginate(path, query, page_size=int(getattr(params, "limit", 0) or 0))
        )
        return rows, "json"
    return api.get(path, query), "json"

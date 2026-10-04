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

import configparser
import getpass
import os
import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction
from collections.abc import Callable, Mapping
from typing import Any

from colorama import Fore

from .lib.remote.client import TocClient
from .lib.remote.config import (
    DEFAULT_BASE_URL,
    SECTION,
    config_path,
    load_settings,
    masked,
    write_credentials,
)
from .lib.remote.contract import ROUTES, Route, required_parameters
from .lib.remote.errors import ConfigurationError, RemoteError
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


def add_init_parser(subparsers: _SubParsersAction[ArgumentParser]) -> None:
    """Add the `init` command.

    **The one command not derived from the route contract**, and the reason
    is categorical rather than a preference: it configures access to the API
    rather than calling it, so there is no route it could be derived from.
    Any future exception needs its own reason and may not cite this one.

    Args:
        subparsers: The top-level subparser action.
    """
    parser = subparsers.add_parser(
        "init",
        help="store a TrustOnCloud API key, and check that it works.",
    )
    parser.set_defaults(api_init=True)


def _read_secret(prompt: str) -> str:
    """Read a secret, suppressing the echo only when there is one.

    `getpass` on a pipe warns that it cannot control the terminal, which is
    noise on the documented CI path where there is no terminal and nothing
    to echo to.

    Args:
        prompt: What to show, when there is anyone to show it to.

    Returns:
        What was read, stripped.
    """
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    return sys.stdin.readline().strip()


def _current_key(env: Mapping[str, str]) -> str:
    """Read the key already in the credentials file, forgivingly.

    Unlike the loader this tolerates anything, because `init` exists to
    repair a file the loader would refuse, including one whose permissions
    are the problem.

    Args:
        env: The environment to read.

    Returns:
        The stored key, or an empty string.
    """
    path = config_path(env)
    if not path.is_file():
        return ""
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
        return parser.get(SECTION, "api_key", fallback="").strip()
    except configparser.Error:
        return ""


def run_init(
    _params: Namespace,
    *,
    env: Mapping[str, str] | None = None,
    read_secret: Callable[[str], str] | None = None,
    read_line: Callable[[str], str] | None = None,
    interactive: bool | None = None,
    client: TocClient | None = None,
) -> None:
    """Store an API key and report whether it works.

    Args:
        _params: The parsed arguments, unused.
        env: The environment to read.
        read_secret: How to read the key without echoing it.
        read_line: How to read a visible answer.
        interactive: Whether to prompt, defaulting to whether stdin is a tty.
        client: A client to verify with, built from the new settings when
            omitted.

    Raises:
        ConfigurationError: If no key is given, or the key is malformed.
    """
    environ = os.environ if env is None else env
    secret = read_secret or _read_secret
    line = read_line or (lambda prompt: input(prompt).strip())
    prompting = sys.stdin.isatty() if interactive is None else interactive

    existing = _current_key(environ)
    api_url = ""

    if prompting:
        if existing:
            print(f"Current key: {masked(existing)}")
        suffix = " (press enter to keep the current one)" if existing else ""
        key = secret(f"TrustOnCloud API key{suffix}: ") or existing
        api_url = line(f"API endpoint (enter for {DEFAULT_BASE_URL}): ")
    else:
        # Piped, so one line and no questions: `echo "$KEY" | tmxcaliber init`
        # works in CI without a tty.
        key = secret("")

    if not key:
        raise ConfigurationError("No API key given, so nothing was written.")

    path = write_credentials(key, api_url=api_url, env=environ)
    print(f"Wrote {path} (readable only by you).")

    if environ.get("TOC_API_KEY", "").strip():
        # It silently wins over the file, so someone who just ran this and
        # still sees the old tenant would have no way to find out why.
        print(
            Fore.YELLOW + "Note: TOC_API_KEY is set, and it takes precedence over this "
            "file. Unset it to use what was just written." + Fore.RESET
        )

    _verify(environ, client)


def _verify(env: Mapping[str, str], client: TocClient | None) -> None:
    """Call /v1/me and say what answered.

    Reported rather than enforced: the key is already written, and a
    verification failure is information about the tenant or the network
    rather than a reason to discard it.

    Args:
        env: The environment to read.
        client: A client to use, built from the resolved settings otherwise.
    """
    try:
        api = client or TocClient(load_settings(env=env))
        who = api.get("/v1/me")
    except RemoteError as exc:
        print(Fore.YELLOW + f"Stored, but the key did not work: {exc}" + Fore.RESET)
        print(
            "If this says not found, the API may not be enabled for your "
            "organization yet, or your address may not be on its allow list."
        )
        return
    tenant = who.get("tenantId", "unknown")
    granted = who.get("permissions") or []
    print(f"Verified. Tenant {tenant}, {len(granted)} permission(s).")

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
    tmxcaliber compliance mappings list --framework nist-800-53-r5
"""

from __future__ import annotations

import configparser
import getpass
import json
import os
import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction
from collections.abc import Callable, Mapping
from typing import Any

from colorama import Fore

from .lib.remote.client import TocClient
from .lib.remote.config import (
    SECTION,
    Settings,
    config_path,
    load_settings,
    masked,
    settings_for,
    write_credentials,
)
from .lib.remote.contract import (
    ROUTES,
    Route,
    required_page_fields,
    required_parameters,
    values_field,
    values_route,
)
from .lib.remote.errors import ConfigurationError, RemoteError
from .lib.remote.ref import parse_ref

#: The namespace key each nesting level of the command tree parks its word in.
#:
#: `operation` is the top level, which the existing commands already use.
LEVEL_DEST = "api_level_{depth}"

#: Page fields that, when not empty, mean the rows are incomplete.
#:
#: The contract says so in each field's description; the code cannot read that,
#: so the names live here, and a test holds each to a route that requires it.
#: A command over such a route exits ``INCOMPLETE_EXIT`` when the API reports
#: missing rows, unless the caller passed ``--allow-incomplete``.
INCOMPLETENESS_FIELDS: tuple[str, ...] = ("unresolvedTmIds",)

#: The exit status of a command whose answer the API reported incomplete.
INCOMPLETE_EXIT = 3

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


def _filter_help(route: Route, name: str, *, required: bool) -> str:
    """Describe one query parameter for a command's help.

    Args:
        route: The route the command reaches.
        name: The parameter, as the API spells it.
        required: Whether the route refuses to answer without it.

    Returns:
        The help text, naming the command that lists the accepted values when
        the API publishes one.
    """
    words = name.replace("_", " ")
    text = f"the {words} to read." if required else f"filter by {words}."
    lookup = values_route(route, name)
    if lookup is not None:
        text += (
            f" Takes a {values_field(name)} as "
            f"`tmxcaliber {' '.join(lookup.command)}` reports it."
        )
    return text


def _summary(route: Route) -> str:
    """Render a command's one-line help, naming what it cannot run without.

    The parent's help is the first screen a caller sees, so a required option
    shown only one level down meant the obvious next command failed.

    Args:
        route: The route the command reaches.

    Returns:
        The summary, with its required options appended.
    """
    needed = sorted(required_parameters(route.path) & set(route.filters))
    if not needed:
        return route.summary
    return f"{route.summary} Requires {', '.join(_option(n) for n in needed)}."


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
    # argparse files every option under "options" whether or not it is
    # required, which made a mandatory --framework read as an optional filter.
    required_group = parser.add_argument_group("required arguments")
    for name in route.filters:
        target = required_group if name in required else parser
        target.add_argument(
            _option(name),
            dest=name,
            default="",
            required=name in required,
            help=_filter_help(route, name, required=name in required),
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
    if _incompleteness_fields(route):
        parser.add_argument(
            "--allow-incomplete",
            action="store_true",
            help=(
                "exit 0 even when the API reports rows it could not resolve. "
                f"Without it the command still writes what it got, then exits "
                f"{INCOMPLETE_EXIT}, so a script cannot take a partial answer "
                "for a whole one."
            ),
        )
    parser.add_argument(
        "--output",
        default="",
        help="file to write the result to. Prints to stdout when omitted.",
    )
    parser.set_defaults(api_route=route)


def _incompleteness_fields(route: Route) -> tuple[str, ...]:
    """List the incompleteness fields a route's pages are required to carry.

    Args:
        route: The route.

    Returns:
        The names, in ``INCOMPLETENESS_FIELDS`` order.
    """
    required = required_page_fields(route.path)
    return tuple(name for name in INCOMPLETENESS_FIELDS if name in required)


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
        leaf = parent.add_parser(
            route.command[-1], help=_summary(route), description=_summary(route)
        )
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


def _report_envelope(envelope: Mapping[str, Any]) -> None:
    """Print what a collection said about itself beyond its rows, on stderr.

    The rows stay the whole of stdout, so a script reading them is unaffected,
    while a person still sees, for example, which ThreatModels a compliance
    mapping could not resolve. Dropping that would present an incomplete
    collection as a complete one. An empty value says nothing and is skipped.

    Args:
        envelope: The page's fields other than the paging ones.
    """
    for name, value in envelope.items():
        if value in (None, "", [], {}):
            continue
        print(
            Fore.YELLOW + f"{name}: {json.dumps(value)}" + Fore.RESET,
            file=sys.stderr,
        )


def run_api_command(
    params: Namespace,
    *,
    client: TocClient | None = None,
    incomplete: list[str] | None = None,
) -> tuple[Any, str]:
    """Execute an API command.

    Args:
        params: The parsed arguments.
        client: A client to use, built from the environment when omitted.
        incomplete: When given, receives one line per incompleteness field the
            API reported as not empty, for the caller to act on after writing
            the result.

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
        envelope: dict[str, Any] = {}
        rows = list(
            api.paginate(
                path,
                query,
                page_size=int(getattr(params, "limit", 0) or 0),
                envelope=envelope,
                required=required_page_fields(route.path),
            )
        )
        _report_envelope(envelope)
        if incomplete is not None:
            incomplete.extend(
                f"{name}: {json.dumps(envelope[name])}"
                for name in _incompleteness_fields(route)
                if envelope.get(name)
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
    parser.add_argument(
        "--api-url",
        metavar="URL",
        default=None,
        help="store this API endpoint instead of the default; omit to keep the "
        "current one.",
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


def _current(env: Mapping[str, str]) -> tuple[str, str]:
    """Read what is already configured, forgivingly.

    **Both values, not just the key.** Reading only the key meant a blank
    answer at the endpoint prompt rewrote the file without the endpoint, so
    re-running `init` to check a setup silently moved it back to the
    default, and the piped form did it with no prompt at all.

    Unlike the loader this tolerates anything, because `init` exists to
    repair a file the loader would refuse, including one whose permissions
    are the problem.

    Args:
        env: The environment to read.

    Returns:
        The stored key and endpoint, either of which may be empty.
    """
    path = config_path(env)
    if not path.is_file():
        return "", ""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
        return (
            parser.get(SECTION, "api_key", fallback="").strip(),
            parser.get(SECTION, "api_url", fallback="").strip(),
        )
    except configparser.Error:
        return "", ""


def run_init(
    params: Namespace,
    *,
    env: Mapping[str, str] | None = None,
    read_secret: Callable[[str], str] | None = None,
    interactive: bool | None = None,
    client: TocClient | None = None,
) -> int:
    """Store an API key and report whether it works.

    **The endpoint is an option, never a question.** Almost everyone uses
    the default, so asking on every run was noise, and an option also
    reaches the piped form that could never ask.

    Args:
        params: The parsed arguments; `api_url` replaces the stored
            endpoint when given.
        env: The environment to read.
        read_secret: How to read the key without echoing it.
        interactive: Whether to prompt, defaulting to whether stdin is a tty.
        client: A client to verify with, built from the new settings when
            omitted.

    Returns:
        0 when the stored key answered, 1 when it did not.

    Raises:
        ConfigurationError: If no key is given, or the key is malformed.
    """
    environ = os.environ if env is None else env
    secret = read_secret or _read_secret
    prompting = sys.stdin.isatty() if interactive is None else interactive

    existing, current_url = _current(environ)
    # Omitted means keep, for the endpoint exactly as for the key. Those two
    # meaning opposite things in one command is what discarded a configured
    # endpoint.
    api_url = (getattr(params, "api_url", None) or "").strip() or current_url

    if prompting:
        if existing:
            print(f"Current key: {masked(existing)}")
        suffix = " (press enter to keep the current one)" if existing else ""
        key = secret(f"TrustOnCloud API key{suffix}: ") or existing
    else:
        # Piped, so one line and no questions: `echo "$KEY" | tmxcaliber init`
        # works in CI without a tty.
        key = secret("")

    if not key:
        raise ConfigurationError("No API key given, so nothing was written.")

    # Built before anything is written, so a malformed key or an endpoint
    # that would carry it in the clear is refused rather than stored.
    #
    # **Verified against the endpoint commands will actually use**, which
    # means TOC_API_URL wins here exactly as it does in `load_settings`.
    # Taking only the stored value meant init could check one API while
    # every later command called another, which is the failure the
    # endpoint precedence fix was supposed to end.
    effective = environ.get("TOC_API_URL", "").strip() or api_url
    settings = settings_for(key, api_url=effective, source="tmxcaliber init")

    path = write_credentials(key, api_url=api_url, env=environ)
    print(f"Wrote {path} (readable only by you).")

    if environ.get("TOC_API_KEY", "").strip():
        # It silently wins over the file, so someone who just ran this and
        # still sees the old tenant would have no way to find out why.
        print(
            Fore.YELLOW + "Note: TOC_API_KEY is set, and it takes precedence over "
            "this file. The check below is of the key just stored; commands will "
            "use the environment one until you unset it." + Fore.RESET
        )

    return _verify(settings, client)


def _verify(settings: Settings, client: TocClient | None) -> int:
    """Call /v1/me with the credential just stored, and say what answered.

    **The settings are passed in rather than resolved.** Resolving consults
    `TOC_API_KEY` first, so with that variable set this reported "Verified"
    for a key the command had not written and never tested, while the one
    in the file went untried.

    **The key is kept either way, and the exit code still says no.** A
    failure here is usually the organization not being enabled yet rather
    than a bad key, so discarding what the caller just typed would be
    unhelpful. Exiting zero would be worse: the documented piped form runs
    in CI, where a setup step that cannot work must not look like one that
    did.

    Args:
        settings: The credential and endpoint just stored.
        client: A client to use, built from those settings otherwise.

    Returns:
        0 when the key answered, 1 when it did not.
    """
    try:
        api = client or TocClient(settings)
        who = api.get("/v1/me")
    except RemoteError as exc:
        print(Fore.YELLOW + f"Stored, but the key did not work: {exc}" + Fore.RESET)
        print(
            "If this says not found, the API may not be enabled for your "
            "organization yet, or your address may not be on its allow list."
        )
        print("The key was kept; nothing else needs re-entering.")
        return 1
    tenant = who.get("tenantId", "unknown")
    granted = who.get("permissions") or []
    # Naming the endpoint, because which one was checked is the thing a
    # caller cannot otherwise tell.
    print(
        f"Verified against {settings.base_url}. "
        f"Tenant {tenant}, {len(granted)} permission(s)."
    )
    return 0

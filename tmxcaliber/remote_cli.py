"""The API commands, built from the contract rather than written out.

Every group, command, positional and option below is derived from an OpenAPI
document, as `lib/remote/contract.py` interprets it: the copy vendored with
this release, or with ``--contract live`` (``--live``) the API's own
definition for the caller's credential. A route the API adds therefore becomes
a command here once the vendored copy is refreshed, or at once under the live
contract, with no naming decision to make and nothing to keep in step by hand.

The shape mirrors the API:

    tmxcaliber me
    tmxcaliber threatmodels list --provider aws
    tmxcaliber threatmodels get aws-s3
    tmxcaliber threatmodels threats aws-s3 --feature-class-id S3.FC1
    tmxcaliber threatmodels dfd aws-s3@1611187200
    tmxcaliber compliance mappings list --framework-id nist-800-53-r5
    tmxcaliber overwatch updates list --live
"""

from __future__ import annotations

import configparser
import getpass
import os
import sys
from argparse import (
    SUPPRESS,
    ArgumentError,
    ArgumentParser,
    Namespace,
    _SubParsersAction,
)
from collections.abc import Callable, Collection, Mapping, Sequence
from typing import Any

from . import console
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
    CONTRACT_NAMES,
    REFERENCE_PARAMETERS,
    RELEASE_OPTION,
    Contract,
    ContractName,
    Option,
    Route,
    python_name,
    values_field,
    vendored,
)
from .lib.remote.errors import ConfigurationError, NotFound, RemoteError
from .lib.remote.live_contract import live_refusal, load_live_contract
from .lib.remote.operations import call_route, incompleteness_fields, read_page, wire
from .lib.remote.ref import is_remote_ref
from .lib.remote.resolve import resolve_source
from .lib.remote.suggest import alternative_names, did_you_mean, suggest

#: The namespace key each nesting level of the command tree parks its word in.
#:
#: `operation` is the top level, which the existing commands already use.
LEVEL_DEST = "api_level_{depth}"

#: The exit status of a command whose answer the API reported incomplete.
INCOMPLETE_EXIT = 3

#: What a positional holds: its metavar, and the noun its help opens with.
POSITIONALS = {"tm_id": ("TMID", "the ThreatModel")}

#: The one command with no route behind it; see `add_init_parser`.
INIT_COMMAND = "init"

#: Namespace keys the CLI sets itself, which a route's argument would overwrite:
#: the top-level command, the selected route and its contract, the contract
#: options every level takes, and the leaf's own options.
CLI_DESTS = frozenset(
    {
        "operation",
        "api_route",
        "api_contract",
        "contract",
        "live",
        "cursor",
        "output",
        "help",
    }
)

#: The message for asking for both contracts at once.
_BOTH_CONTRACTS = (
    "--live and --contract vendored ask for different contracts; give one."
)


def _escaped(text: str) -> str:
    """Make text from the contract safe as argparse help.

    Args:
        text: The help text.

    Returns:
        The text with ``%`` doubled, since argparse formats help with it.
    """
    return text.replace("%", "%%")


def _option(filter_name: str) -> str:
    """Render a query parameter as its command-line option.

    Args:
        filter_name: The parameter name as the API spells it.

    Returns:
        The option, with word boundaries rendered as dashes.
    """
    return f"--{python_name(filter_name).replace('_', '-')}"


def _filter_help(contract: Contract, route: Route, option: Option) -> str:
    """Describe one query parameter for a command's help.

    The contract's own description wins when it has one: it is the API's
    statement of what the filter matches, which no wording derived from the
    parameter's name can be.

    Args:
        contract: The contract the command tree is built from, which says
            which command lists the values.
        route: The route the command reaches.
        option: The parameter.

    Returns:
        The contract's description of the parameter, then the command that
        lists the accepted values when the API publishes one, then the
        default when the contract declares one.
    """
    words = _option(option.name)[2:].replace("-", " ")
    if option.description:
        text = option.description
    elif option.required:
        text = f"the {words} to read."
    else:
        text = f"filter by {words}."
    # The contract's description already says so where it has one.
    if option.repeatable and not option.description:
        text += " Repeat it to match any of several."
    lookup = contract.values_route(route, option.name)
    if lookup is not None:
        text += (
            f" Takes a {values_field(option.name)} as "
            f"`tmxcaliber {' '.join(lookup.command)}` reports it."
        )
    if option.default is not None:
        text += f" Defaults to {option.default}."
    return _escaped(text)


def _positional_help(contract: Contract, route: Route) -> tuple[str, str]:
    """Name and describe a command's positional.

    Args:
        contract: The contract the command tree is built from, which says
            which command lists what the positional takes.
        route: The route the command reaches; it takes a positional.

    Returns:
        The metavar, and the help naming the command whose rows it takes.
    """
    positional = route.positional or ""
    metavar, noun = POSITIONALS.get(
        positional, (positional.upper(), f"the {positional.replace('_', ' ')}")
    )
    text = noun
    listing = contract.listing_route(route)
    if listing is not None:
        text += f", as `{' '.join(listing.command)}` reports it"
    if (
        route.path_parameters == REFERENCE_PARAMETERS
        and RELEASE_OPTION in route.filters
    ):
        text += ", optionally pinned with @release (for example aws-s3@1611187200)"
    return metavar, _escaped(f"{text}.")


def _summary(route: Route) -> str:
    """Render a command's one-line help, naming what it cannot run without.

    The parent's help is the first screen a caller sees, so a required option
    shown only one level down meant the obvious next command failed.

    Args:
        route: The route the command reaches.

    Returns:
        The summary, with its required options appended.
    """
    needed = sorted(option.name for option in route.options if option.required)
    if not needed:
        return _escaped(route.summary)
    required = ", ".join(_option(name) for name in needed)
    return _escaped(f"{route.summary} Requires {required}.")


def _leaf(parser: ArgumentParser, route: Route, contract: Contract) -> None:
    """Add one route's arguments to its parser.

    Args:
        parser: The parser for this command.
        route: The route it reaches.
        contract: The contract the route was bound from.
    """
    if route.positional:
        metavar, help_text = _positional_help(contract, route)
        parser.add_argument(route.positional, metavar=metavar, help=help_text)
    # argparse files every option under "options" whether or not it is
    # required, which made a mandatory --framework-id read as an optional filter.
    required_group = parser.add_argument_group("required arguments")
    for option in route.options:
        target = required_group if option.required else parser
        target.add_argument(
            _option(option.name),
            dest=python_name(option.name),
            type=option.kind,
            choices=option.choices or None,
            # Given once per value, as the API takes it; argparse checks each
            # value against the choices.
            action="append" if option.repeatable else "store",
            default=None,
            required=option.required,
            help=_filter_help(contract, route, option),
        )
    if route.paged:
        largest = route.page_maximum
        # One page is the only answer a list command gives: reading the whole
        # collection by default once spent a key's hourly budget on one
        # OverWatch list, because --limit sized the requests, not the answer.
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help=(
                "rows to return, the API's own default when omitted"
                + (f", at most {largest}" if largest else "")
                + '. The command reads one page and writes it as {"items": [...], '
                '"nextCursor": ...}; nextCursor is null on the last page.'
            ),
        )
        parser.add_argument(
            "--cursor",
            default="",
            help="read the page after the one that returned this nextCursor, "
            "with the same filters.",
        )
    if incompleteness_fields(route):
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
        # A zip printed to a terminal is noise at best, so a binary route
        # refuses to run without a file.
        required=route.binary,
        help=(
            "file to write the archive to."
            if route.binary
            else "file to write the result to. Prints to stdout when omitted."
        ),
    )
    add_contract_arguments(parser)
    parser.set_defaults(api_route=route, api_contract=contract)


def add_contract_arguments(parser: ArgumentParser, *, root: bool = False) -> None:
    """Let a parser take the choice of contract.

    Declared at every level of the API tree, so ``--live`` reads the same
    wherever it is typed: ``tmxcaliber --live overwatch updates list`` and
    ``tmxcaliber overwatch updates list --live`` alike. **No level has a
    default**, because argparse copies each subcommand's results over its
    parent's, and a default one level down would erase a choice made above
    it. The choice itself was already read from argv by `requested_contract`,
    before the tree was built from it; parsing it here is what makes argparse
    accept it and list it in the help.

    Args:
        parser: The root parser, an API group's, or an API command's.
        root: Whether it is the root parser, whose help is laid out by hand.
    """
    gap = "\n\n" if root else ""
    group = parser.add_argument_group("API contract")
    group.add_argument(
        "--contract",
        choices=CONTRACT_NAMES,
        default=SUPPRESS,
        help=(
            "which definition the API commands are built from: vendored, the "
            "one this release ships with (the default), or live, the one the "
            "API serves your credential, which adds what your tenant has "
            f"before every tenant does. Live costs two calls per command.{gap}"
        ),
    )
    group.add_argument(
        "--live",
        action="store_true",
        default=SUPPRESS,
        help=f"short for --contract live.{gap}",
    )


def requested_contract(argv: Sequence[str], local: Collection[str]) -> ContractName:
    """Read which contract a command line asks for, before it is parsed.

    The API commands are built from the contract, so the choice has to be
    known before argparse can parse the line that makes it. A local command,
    or `init`, never asks for one: neither is built from the contract, so no
    call is spent, and argparse then refuses the option there itself.

    Args:
        argv: The arguments after the program name.
        local: The top-level commands that are not built from the contract.

    Returns:
        ``"live"`` when ``--live``, ``--contract live`` or ``--contract=live``
        precedes any ``--``, with the last ``--contract`` winning, and
        ``"vendored"`` otherwise. A value argparse will refuse counts as
        vendored, so it is refused without a call.

    Raises:
        ValueError: If ``--live`` and ``--contract vendored`` are both given.
    """
    live = False
    explicit: str | None = None
    first: str | None = None
    tokens = iter(argv)
    for token in tokens:
        if token == "--":
            break
        if token == "--live":
            live = True
        elif token == "--contract":
            explicit = next(tokens, None)
        elif token.startswith("--contract="):
            explicit = token.partition("=")[2]
        elif first is None and not token.startswith("-"):
            first = token
    if first in local:
        return "vendored"
    if live and explicit == "vendored":
        raise ValueError(_BOTH_CONTRACTS)
    return "live" if live or explicit == "live" else "vendored"


def load_contract(name: ContractName) -> Contract:
    """Load the contract a command line asked for.

    Args:
        name: The contract `requested_contract` read.

    Returns:
        The vendored contract, which costs nothing, or the live one, read
        through `connect` with the caller's own credential.

    Raises:
        RemoteError: If the live contract cannot be read or bound.
    """
    if name == "vendored":
        return vendored()
    return load_live_contract(connect())


def settle_contract(
    parser: ArgumentParser, params: Namespace, requested: ContractName
) -> None:
    """Hold what argparse parsed to the contract the tree was built from.

    `requested_contract` reads the exact spellings; argparse also accepts an
    abbreviation such as ``--liv``, which would otherwise ask for one
    contract on a tree built from the other.

    Args:
        parser: The root parser, which reports a mismatch as a usage error.
        params: The parsed arguments.
        requested: The contract the tree was built from.
    """
    explicit = getattr(params, "contract", None)
    live = bool(getattr(params, "live", False))
    if live and explicit == "vendored":
        parser.error(_BOTH_CONTRACTS)
    if selected_route(params) is None:
        if live or explicit is not None:
            parser.error("--live and --contract apply only to the API commands.")
        return
    parsed: ContractName = "live" if live or explicit == "live" else "vendored"
    if parsed != requested:
        parser.error(
            "--live and --contract choose the contract the commands are built "
            "from, so they are read before parsing; spell them out in full."
        )


def selected_contract(params: Namespace) -> Contract:
    """Report which contract the selected API command was built from.

    Args:
        params: The parsed arguments.

    Returns:
        The contract, or the vendored one when the arguments name none.
    """
    found = getattr(params, "api_contract", None)
    return found if isinstance(found, Contract) else vendored()


def add_api_parsers(
    subparsers: _SubParsersAction[ArgumentParser], contract: Contract | None = None
) -> None:
    """Build every API command onto the top-level parser.

    Args:
        subparsers: The top-level subparser action.
        contract: The contract to build from, the vendored one when omitted.

    Raises:
        ValueError: If a vendored route clashes with a local command or the
            CLI's own arguments, which CI catches.
        ContractViolation: If a live route does, which only a definition newer
            than this release can.
    """
    contract = contract or vendored()
    try:
        _add_api_parsers(subparsers, contract)
    except (ValueError, ArgumentError) as exc:
        if not contract.live:
            raise
        raise live_refusal(exc) from exc


def _add_api_parsers(
    subparsers: _SubParsersAction[ArgumentParser], contract: Contract
) -> None:
    """Build every route of one contract onto the top-level parser.

    Args:
        subparsers: The top-level subparser action.
        contract: The contract to build from.
    """
    # One parser per group prefix, created on first use so the tree is built
    # from the interpreted contract rather than spelled out.
    groups: dict[tuple[str, ...], _SubParsersAction[ArgumentParser]] = {}

    for route in contract.routes:
        parent: _SubParsersAction[ArgumentParser] = subparsers
        if len(route.command) == 1 or route.command[:1] not in groups:
            _refuse_local_command(subparsers, route.command[0], route)
        _refuse_cli_names(route)
        for depth, word in enumerate(route.command[:-1]):
            prefix = route.command[: depth + 1]
            if prefix not in groups:
                group_parser = parent.add_parser(
                    word, help=f"{word} operations against the TrustOnCloud API."
                )
                add_contract_arguments(group_parser)
                groups[prefix] = group_parser.add_subparsers(
                    dest=LEVEL_DEST.format(depth=depth + 1), required=True
                )
            parent = groups[prefix]
        leaf = parent.add_parser(
            route.command[-1], help=_summary(route), description=_summary(route)
        )
        _leaf(leaf, route, contract)


def _refuse_local_command(
    subparsers: _SubParsersAction[ArgumentParser], word: str, route: Route
) -> None:
    """Refuse a top-level API command word a local command already answers to.

    Args:
        subparsers: The top-level subparser action.
        word: The API command's first word.
        route: The route, for the message.

    Raises:
        ValueError: If ``word`` is a local command, or `init`.
    """
    if word in subparsers.choices or word == INIT_COMMAND:
        raise ValueError(
            f"{route.path}: the command word {word!r} is already a tmxcaliber command."
        )


def _refuse_cli_names(route: Route) -> None:
    """Refuse a route argument that would overwrite one the CLI sets itself.

    argparse merges every level's results into one namespace, so a filter
    named ``operation`` would silently replace the command being dispatched.

    Args:
        route: The route.

    Raises:
        ValueError: If an option or the positional takes a name in
            `CLI_DESTS` or a command-level key.
    """
    names = [python_name(option.name) for option in route.options]
    if route.positional:
        names.append(route.positional)
    level_prefix = LEVEL_DEST.split("{", 1)[0]
    taken = [n for n in names if n in CLI_DESTS or n.startswith(level_prefix)]
    if taken:
        raise ValueError(
            f"{route.path}: {', '.join(taken)} would overwrite the CLI's own arguments."
        )


def selected_route(params: Namespace) -> Route | None:
    """Report which API route a parsed command reaches.

    Args:
        params: The parsed arguments.

    Returns:
        The route, or None when the command is not an API command.
    """
    route = getattr(params, "api_route", None)
    return route if isinstance(route, Route) else None


#: Stored-endpoint notes this process has already written. A process is one
#: invocation, and `create-change-log` can resolve two references in it;
#: the same note twice would read like two different problems.
_noted: set[tuple[str, str]] = set()


def _note_stored_endpoint(settings: Settings) -> None:
    """Say, on stderr, that an environment key is going to a stored endpoint.

    The endpoint is resolved independently of the key, so a key exported in
    TOC_API_KEY goes to whatever endpoint `init` stored unless TOC_API_URL
    names another. That precedence is deliberate and stays; this only makes
    it visible. Written before any request, so the reader learns it even
    when the call then fails, and on stderr, so JSON on stdout is untouched.

    Args:
        settings: The settings a command is about to use.
    """
    if not settings.sends_key_to_stored_endpoint:
        return
    said = (settings.base_url, settings.endpoint_source)
    if said in _noted:
        return
    _noted.add(said)
    console.stderr().line(settings.stored_endpoint_note, "yellow")


def connect(env: Mapping[str, str] | None = None) -> TocClient:
    """Build the client a command uses when none was given.

    **Every command that resolves settings from the environment and the file
    comes through here**, the API commands and a ThreatModel reference given
    as a document source alike, so what the reader is told about those
    settings is said in one place. `init` is the deliberate exception: it
    verifies the key it just stored rather than what resolution would pick.

    Args:
        env: The environment to read, defaulting to the real one.

    Returns:
        A client over the resolved settings.

    Raises:
        ConfigurationError: If no usable credential is configured.
    """
    settings = load_settings(env=env)
    _note_stored_endpoint(settings)
    return TocClient(settings)


def resolve_command_source(source: str) -> str:
    """Resolve a document command's source, reaching the API through `connect`.

    Args:
        source: A filesystem path, a directory, or a ThreatModel reference.

    Returns:
        A path. The input unchanged when it was already one.

    Raises:
        RemoteError: On any transport, credential or server failure.
    """
    return resolve_source(source, connect=connect)


#: For a positional that names something the API lists, the row field holding
#: each name and the row field holding its title when there is one, by the
#: path of the collection that lists it. That collection is the route's path
#: up to its first parameter, so `ccr packs get` and `ccr packs archive` both
#: look in `ccr packs list`, and every `threatmodels` command looks in
#: `threatmodels list`. Both lists name their rows by `tmId`, and both kinds of
#: route call their positional `tm_id`, so the positional alone cannot say
#: which list to read.
NAME_LISTS: Mapping[str, tuple[str, str | None]] = {
    "/v1/ccr/packs": ("tmId", None),
    "/v1/threatmodels": ("tmId", "title"),
}


def _did_you_mean(
    client: TocClient, contract: Contract, route: Route, typed: str
) -> str:
    """Say which listed name a positional the API does not know probably meant.

    The command line asks only after a ``NotFound``, so a name typed right
    costs no extra call, and `Client`'s route methods never ask, so a library
    caller makes exactly the calls it wrote. Only what this key can list is
    suggested, so a ThreatModel or pack outside its subscription is never
    named.

    Args:
        client: The client the command used.
        contract: The contract the command was built from, which binds the
            list to read.
        route: The route that answered ``NotFound``.
        typed: The positional as typed, with any ``@release``.

    Returns:
        The ``Did you mean ...?`` sentence, with each ThreatModel's title
        after its id. A ThreatModel's own title and the short form in its
        brackets both lead to it, as the list publishes them, so its official
        name typed back is never a stranger to the suggestion. Empty when the
        route names nothing the API lists, when no name was typed, when
        nothing listed is close, when the name is itself listed (as when only
        its release is unknown), or when the list cannot be read, in which
        case the API's own error is the one worth reporting.
    """
    collection = route.path.partition("{")[0].rstrip("/")
    lookup = NAME_LISTS.get(collection) if route.positional else None
    if lookup is None:
        return ""
    # A release pins a version of the name, and is no part of the name itself.
    wanted = typed.partition("@")[0]
    if not wanted:
        return ""
    name_field, title_field = lookup
    listing = contract.route_for_path(collection)
    assert listing is not None, f"{collection} is not bound"
    try:
        rows = call_route(client, listing, "", {}).result
    except RemoteError:
        return ""
    names = [str(row.get(name_field) or "") for row in rows]
    labels = (
        {
            str(row.get(name_field) or ""): str(row.get(title_field) or "")
            for row in rows
        }
        if title_field
        else None
    )
    # A ThreatModel is also known by the title it was published under, so the
    # row's own words lead back to it. Only fields the contract declares are
    # read, because the API strips any other before answering.
    published = (
        {
            str(row.get(name_field) or ""): alternative_names(
                str(row.get(title_field) or "")
            )
            for row in rows
        }
        if title_field
        else None
    )
    found = suggest(wanted, [name for name in names if name], extra_aliases=published)
    return did_you_mean(found, labels)


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
        The result and the result type `output_result` expects: "bytes" for a
        binary route, "json" otherwise. The result of a paged route is one
        page as the API served it, ``items`` and ``nextCursor`` included.

    Raises:
        NotFound: If the API does not know the ThreatModel or pack named.
            When one this key can list is close to the name typed, its
            ``did_you_mean`` holds the ``Did you mean ...?`` sentence, which
            ``str()`` puts after the message, and the code, status and request
            id stay the API's. A ThreatModel typed in a shape no
            reference has, such as ``Amazon EC2``, is refused before the API
            is asked, and raises this too, with no status or request id, when
            a listed one is close to it.
        RemoteError: On any other credential, transport or server failure.
        ValueError: If a ThreatModel reference cannot be parsed, and none the
            key can list is close to it, or is pinned for a route that takes
            no release.
    """
    route = selected_route(params)
    assert route is not None, "run_api_command called for a non-API command"
    contract = selected_contract(params)
    api = client or connect()
    typed = str(getattr(params, route.positional, "") or "") if route.positional else ""
    # The API spells a filter in camelCase and argparse keeps it in snake_case.
    filters = {
        option.name: wire(
            getattr(params, python_name(option.name), None),
            repeatable=option.repeatable,
        )
        for option in route.options
    }
    limit = int(getattr(params, "limit", 0) or 0)
    cursor = str(getattr(params, "cursor", "") or "")
    try:
        if route.paged:
            answer = read_page(api, route, typed, filters, limit=limit, cursor=cursor)
        else:
            answer = call_route(api, route, typed, filters)
    except NotFound as exc:
        sentence = _did_you_mean(api, contract, route, typed)
        if not sentence:
            raise
        raise NotFound(
            Exception.__str__(exc),
            code=exc.code,
            request_id=exc.request_id,
            status=exc.status,
            did_you_mean=sentence,
        ) from exc
    except ValueError as exc:
        # A ThreatModel typed as "Amazon EC2" is refused by the reference
        # grammar before any request is made, so no 404 follows and the name
        # would never reach the suggestion. The refusal stays as it was when
        # nothing listed is close, and when the reference is well formed and
        # only its release is wrong. A pack's routes send their ThreatModel id
        # as one encoded path segment and parse no reference, so only a route
        # with {provider} in its path is refused this way.
        sentence = (
            _did_you_mean(api, contract, route, typed)
            if "{provider}" in route.path and not is_remote_ref(typed)
            else ""
        )
        if not sentence:
            raise
        # The API never saw the name, so there is no status or request id.
        raise NotFound(str(exc), code="not_found", did_you_mean=sentence) from exc
    if incomplete is not None:
        incomplete.extend(answer.missing)
    return answer.result, "bytes" if route.binary else "json"


def add_init_parser(subparsers: _SubParsersAction[ArgumentParser]) -> None:
    """Add the `init` command.

    **The one command not derived from the API contract**, and the reason
    is categorical rather than a preference: it configures access to the API
    rather than calling it, so there is no route it could be derived from.
    Any future exception needs its own reason and may not cite this one.

    Args:
        subparsers: The top-level subparser action.
    """
    parser = subparsers.add_parser(
        INIT_COMMAND,
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
        console.stdout().line(
            "Note: TOC_API_KEY is set, and it takes precedence over this file. "
            "The check below is of the key just stored; commands will use the "
            "environment one until you unset it.",
            "yellow",
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
        console.stdout().line(f"Stored, but the key did not work: {exc}", "yellow")
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

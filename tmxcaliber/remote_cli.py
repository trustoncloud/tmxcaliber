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
from pathlib import Path
from typing import Any

from colorama import Fore

from .lib.remote.ccr import MATCHERS, MODES, RuleFilter, fetch
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
    required_parameters,
    route_for,
    values_field,
    values_route,
)
from .lib.remote.errors import (
    ConfigurationError,
    NoPackMatched,
    NotFound,
    RemoteError,
)
from .lib.remote.operations import call_route, incompleteness_fields
from .lib.remote.ref import is_remote_ref
from .lib.remote.resolve import resolve_source
from .lib.remote.suggest import alternative_names, did_you_mean, suggest

#: The namespace key each nesting level of the command tree parks its word in.
#:
#: `operation` is the top level, which the existing commands already use.
LEVEL_DEST = "api_level_{depth}"

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

#: Help for an option that "filter by ..." would misdescribe, by route path and
#: then option. The archive route's options choose which file comes back, and
#: narrow no collection, so the generated text would tell the reader nothing
#: about what to pass. Every option not listed here keeps the generated text.
OPTION_HELP: Mapping[str, Mapping[str, str]] = {
    "/v1/ccr/packs/{releaseKey}/archive": {
        "kind": (
            "which archive to download: source (the default, the rule tree) or "
            "deploy (the Terraform package)."
        ),
        "release": (
            "the release to pin the download to, as `tmxcaliber ccr packs get` "
            "reports it; the API refuses a release it no longer publishes."
        ),
    },
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
        The route's own text for the option in `OPTION_HELP` when it has one.
        Otherwise the generated text, naming the command that lists the
        accepted values when the API publishes one.
    """
    written = OPTION_HELP.get(route.path, {}).get(name)
    if written is not None:
        return written
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
        leaf = parent.add_parser(
            route.command[-1], help=_summary(route), description=_summary(route)
        )
        _leaf(leaf, route)

    # The one hand-written command under an API group. It composes routes the
    # loop above bound, and names no route of its own.
    _add_ccr_fetch(groups[("ccr",)])


def _add_ccr_fetch(ccr: _SubParsersAction[ArgumentParser]) -> None:
    """Add `ccr fetch` under the `ccr` group.

    Args:
        ccr: The `ccr` group's subparser action.
    """
    summary = (
        "Select CCR rules by pack, control, mode, matcher or file, and write "
        "their Rego and metadata with --out."
    )
    parser = ccr.add_parser("fetch", help=summary, description=summary)
    parser.add_argument(
        "release_keys",
        nargs="*",
        metavar="RELEASEKEY",
        help="packs to read, as `tmxcaliber ccr packs list` reports them. "
        "Every entitled pack when omitted.",
    )
    for name, help_text in (
        ("provider", "read only this provider's packs, for example aws."),
        (
            "service",
            "read only this service's packs, for example s3. A whole release "
            "key, such as aws-s3, names its pack too.",
        ),
        ("control", "select this control, for example S3.C20."),
        ("file", "select files whose <rule id>/<file> matches this glob."),
    ):
        parser.add_argument(
            f"--{name}", action="append", default=[], help=help_text + " Repeatable."
        )
    parser.add_argument(
        "--mode",
        action="append",
        default=[],
        choices=MODES,
        help="select rules that ship this mode, and only its files. Repeatable.",
    )
    parser.add_argument(
        "--matcher",
        action="append",
        default=[],
        choices=MATCHERS,
        help="select rules that implement this matcher, and only its files. "
        "Repeatable.",
    )
    parser.add_argument(
        "--out",
        default="",
        metavar="DIR",
        help="write the selected files to DIR/<release key>/<rule id>/. "
        "Prints the selected rules as JSON when omitted.",
    )
    parser.set_defaults(ccr_fetch=True)


def run_ccr_fetch(params: Namespace, *, client: TocClient | None = None) -> int:
    """Execute `ccr fetch`.

    The files written for the packs that completed are printed even when
    another pack failed, and each failed pack gets one line on stderr saying
    at which stage it failed and why, ending with the packs it was probably
    meant to be when it was named and is unknown.

    Args:
        params: The parsed arguments.
        client: A client to use, built from the environment when omitted.

    Returns:
        The exit status: 0, 1 when a pack failed or the provider or service
        given matches no pack this key can read, 2 for a usage error.

    Raises:
        RemoteError: On a failure that is not one pack's alone, such as a
            credential failure.
    """
    if params.release_keys and (params.provider or params.service):
        print(
            Fore.RED
            + "Name packs, or narrow by --provider and --service, not both."
            + Fore.RESET,
            file=sys.stderr,
        )
        return 2
    try:
        result = fetch(
            client or connect(),
            release_keys=tuple(params.release_keys),
            providers=tuple(params.provider),
            services=tuple(params.service),
            wanted=RuleFilter(
                controls=tuple(params.control),
                modes=tuple(params.mode),
                matchers=tuple(params.matcher),
                files=tuple(params.file),
            ),
            out=Path(params.out) if params.out else None,
        )
    except NoPackMatched as exc:
        # Said on stderr like a failed pack, because the narrowing is what went
        # wrong. Printing "[]" and "No rule matched" would read as packs that
        # lack such a rule.
        print(Fore.RED + str(exc) + Fore.RESET, file=sys.stderr)
        return 1
    if params.out:
        for path in result.written:
            print(path)
    else:
        print(json.dumps(result.rows, indent=2))
    if not result.rows and not result.failed:
        print(
            Fore.YELLOW + "No rule matched the filters given." + Fore.RESET,
            file=sys.stderr,
        )
    for key, failure in result.failed.items():
        print(Fore.RED + f"{key}: {failure}" + Fore.RESET, file=sys.stderr)
    return 1 if result.failed else 0


def selected_route(params: Namespace) -> Route | None:
    """Report which API route a parsed command reaches.

    Args:
        params: The parsed arguments.

    Returns:
        The route, or None when the command is not an API command.
    """
    route = getattr(params, "api_route", None)
    return route if isinstance(route, Route) else None


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
    print(Fore.YELLOW + settings.stored_endpoint_note + Fore.RESET, file=sys.stderr)


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


#: For a positional that names something the API lists, the command that lists
#: it, the row field holding each name, and the row field holding its title
#: when there is one.
NAME_LISTS: Mapping[str, tuple[tuple[str, ...], str, str | None]] = {
    "release_key": (("ccr", "packs", "list"), "releaseKey", None),
    "tm_id": (("threatmodels", "list"), "tmId", "title"),
}


#: The row fields that list the other services a ThreatModel covers, spelled as
#: the catalogue spells it and as the API's camelCase would.
COVERED_FIELDS: tuple[str, ...] = ("other_covered_services", "otherCoveredServices")


def _published_names(row: Mapping[str, Any], title_field: str) -> tuple[str, ...]:
    """Collect the names a list row publishes for the thing it describes.

    Args:
        row: One row of a list.
        title_field: The row field holding its title.

    Returns:
        The title as published and the forms of it people type, then the same
        for each service the row says it also covers. Every name comes from the
        row, so a suggestion made with them still names only what the list
        showed.
    """
    covered = [
        str(service)
        for field in COVERED_FIELDS
        if isinstance(row.get(field), list)
        for service in row[field]
    ]
    return alternative_names(str(row.get(title_field) or ""), *covered)


def _then(message: str, sentence: str) -> str:
    """Follow a message with a sentence of its own.

    Args:
        message: What an error said.
        sentence: What to add.

    Returns:
        The two, with a full stop between them when the message has none, which
        would otherwise run the two sentences together. A message that already
        ends a sentence gets no second stop, which would read as a typing slip.
    """
    stop = "" if message.endswith((".", "!", "?")) else "."
    return f"{message}{stop} {sentence}"


def _did_you_mean(client: TocClient, route: Route, typed: str) -> str:
    """Say which listed name a positional the API does not know probably meant.

    The command line asks only after a ``NotFound``, so a name typed right
    costs no extra call, and `Client`'s route methods never ask, so a library
    caller makes exactly the calls it wrote. Only what this key can list is
    suggested, so a ThreatModel or pack outside its subscription is never
    named.

    Args:
        client: The client the command used.
        route: The route that answered ``NotFound``.
        typed: The positional as typed, with any ``@release``.

    Returns:
        The ``Did you mean ...?`` sentence, with each ThreatModel's title
        after its id. A ThreatModel's own title, the short form in its
        brackets, and the services it also covers all lead to it, as the list
        publishes them, so its official name typed back is never a stranger to
        the suggestion. Empty when the route names nothing the API lists, when
        no name was typed, when nothing listed is close, when the name is
        itself listed (as when only its release is unknown), or when the list
        cannot be read, in which case the API's own error is the one worth
        reporting.
    """
    lookup = NAME_LISTS.get(route.positional or "")
    if lookup is None:
        return ""
    # A release pins a version of the name, and is no part of the name itself.
    wanted = typed.partition("@")[0]
    if not wanted:
        return ""
    command, name_field, title_field = lookup
    listing = route_for(command)
    assert listing is not None, f"{' '.join(command)} is not bound"
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
    # A ThreatModel is also known by the title it was published under, and by
    # the services it covers, so each row's own words lead back to it.
    published = (
        {
            str(row.get(name_field) or ""): _published_names(row, title_field)
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
        binary route, "json" otherwise.

    Raises:
        NotFound: If the API does not know the ThreatModel or pack named.
            When one this key can list is close to the name typed, the
            message ends with ``Did you mean ...?``, and the code, status and
            request id stay the API's. A ThreatModel typed in a shape no
            reference has, such as ``Amazon EC2``, is refused before the API
            is asked, and raises this too, with no status or request id, when
            a listed one is close to it.
        RemoteError: On any other credential, transport or server failure.
        ValueError: If a ThreatModel reference cannot be parsed, and none the
            key can list is close to it.
    """
    route = selected_route(params)
    assert route is not None, "run_api_command called for a non-API command"
    api = client or connect()
    typed = str(getattr(params, route.positional, "") or "") if route.positional else ""
    filters = {name: str(getattr(params, name, "") or "") for name in route.filters}
    limit = int(getattr(params, "limit", 0) or 0)
    try:
        answer = call_route(api, route, typed, filters, limit=limit)
    except NotFound as exc:
        sentence = _did_you_mean(api, route, typed)
        if not sentence:
            raise
        raise NotFound(
            _then(Exception.__str__(exc), sentence),
            code=exc.code,
            request_id=exc.request_id,
            status=exc.status,
        ) from exc
    except ValueError as exc:
        # A ThreatModel typed as "Amazon EC2" is refused by the reference
        # grammar before any request is made, so no 404 follows and the name
        # would never reach the suggestion. The refusal stays as it was when
        # nothing listed is close, and when the reference is well formed and
        # only its release is wrong.
        sentence = (
            _did_you_mean(api, route, typed)
            if route.positional == "tm_id" and not is_remote_ref(typed)
            else ""
        )
        if not sentence:
            raise
        # The API never saw the name, so there is no status or request id.
        raise NotFound(_then(str(exc), sentence), code="not_found") from exc
    if route.paged:
        _report_envelope(answer.envelope)
    if incomplete is not None:
        incomplete.extend(answer.missing)
    return answer.result, "bytes" if route.binary else "json"


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

"""The TrustOnCloud API as a Python object, shaped like the CLI.

Every attribute path on a `Client` is a CLI command with the spaces turned
into dots, built at construction from the same routes the CLI is built from
(one `contract.Contract`, the vendored OpenAPI document unless the API's live
definition is asked for). Nothing here names a route, so a route the API adds
is a method here and a command there, with no naming decision in between:

    from tmxcaliber import Client

    api = Client()                         # tmxcaliber me
    api.me()
    page = api.threatmodels.list(provider="aws")
    api.threatmodels.list(provider="aws", cursor=page["nextCursor"])
    api.threatmodels.list(provider="aws", limit=300)  # up to 300 rows
    api.threatmodels.threats("aws-s3", feature_class_id="S3.FC1")

    live = Client(contract="live")         # tmxcaliber overwatch updates list --live
    live.overwatch.updates.list()

A route's positional is the method's one positional argument, its filters are
keyword arguments, and a paged route returns one page, as the CLI does, or up
to ``limit=`` rows read across pages: its ``items`` and a ``nextCursor`` that
``cursor=`` continues from. ``page_size=`` sizes each request.
"""

from __future__ import annotations

import inspect
import urllib.request
import warnings
from typing import Any

from .client import QueryValue, TocClient
from .config import DEFAULT_TIMEOUT, load_settings
from .contract import CONTRACT_NAMES, ContractName, Route, python_name, vendored
from .errors import IncompleteAnswer
from .live_contract import live_refusal, load_live_contract
from .operations import Answer, call_route, incompleteness_fields, read_pages, wire


def _signature(route: Route) -> inspect.Signature:
    """Describe the call that reaches a route, the way its CLI command reads.

    Args:
        route: The route.

    Returns:
        A positional-only parameter for the route's positional, a keyword-only
        one per filter (without a default when the API requires it), then
        ``limit``, ``page_size`` and ``cursor`` for a paged route and
        ``allow_incomplete`` for a route whose pages can report missing rows.
    """
    keyword = inspect.Parameter.KEYWORD_ONLY
    parameters = [
        inspect.Parameter(
            python_name(option.name),
            keyword,
            default=inspect.Parameter.empty if option.required else None,
        )
        for option in route.options
    ]
    if route.positional:
        parameters.insert(
            0, inspect.Parameter(route.positional, inspect.Parameter.POSITIONAL_ONLY)
        )
    if route.paged:
        # 0 for both reads one page of the API's own default size.
        parameters.append(inspect.Parameter("limit", keyword, default=0))
        parameters.append(inspect.Parameter("page_size", keyword, default=0))
        parameters.append(inspect.Parameter("cursor", keyword, default=""))
    if incompleteness_fields(route):
        parameters.append(inspect.Parameter("allow_incomplete", keyword, default=False))
    return inspect.Signature(parameters)


class Operation:
    """One API route, called like its CLI command.

    Args:
        client: The client the call goes through.
        route: The route this operation reaches.
    """

    #: Read by `inspect.signature`, so `help()` and argument errors show the
    #: route's own parameters rather than ``*args, **kwargs``.
    __signature__: inspect.Signature

    def __init__(self, client: TocClient, route: Route) -> None:
        self._client = client
        self._route = route
        self.__signature__ = _signature(route)
        self.__doc__ = route.summary

    def __repr__(self) -> str:
        """Name the operation by its command and its call shape.

        Returns:
            For example ``<threatmodels.threats(tm_id, /, *, ...)>``.
        """
        return f"<{'.'.join(self._route.command)}{self.__signature__}>"

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call the route.

        Args:
            *args: The route's positional, when it has one.
            **kwargs: The route's filters, ``limit``, ``page_size``,
                ``cursor`` and ``allow_incomplete``, as the signature lists
                them. ``limit`` is the most rows to read across pages, one
                page when 0; ``page_size`` the rows per request, the API's
                default when 0; ``cursor`` a previous answer's
                ``nextCursor``, bound to the filters it was read with.

        Returns:
            For a paged route, ``items`` and a ``nextCursor`` that continues
            after them, null once the collection is exhausted, beside any
            other field the page reported; the bytes of a binary route; or
            the object any other route returns.

        Raises:
            TypeError: If the arguments do not match the signature.
            IncompleteAnswer: If the API reported rows it could not resolve
                and ``allow_incomplete`` was not set.
            InvalidCursor: If the API does not accept the cursor.
            RemoteError: On any other credential, transport or server failure.
            ValueError: If a ThreatModel reference cannot be parsed.
        """
        positional, filters, values = self._bind(args, kwargs)
        route = self._route
        if route.paged:
            answer = read_pages(
                self._client,
                route,
                positional,
                filters,
                limit=int(values.get("limit", 0) or 0),
                page_size=int(values.get("page_size", 0) or 0),
                cursor=str(values.get("cursor", "") or ""),
            )
        else:
            answer = call_route(self._client, route, positional, filters)
        return _accepted(answer, values)

    def _bind(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, QueryValue], dict[str, Any]]:
        """Read a call's arguments as the route's positional and filters.

        Args:
            args: The positional arguments given.
            kwargs: The keyword arguments given.

        Returns:
            The positional, the filters as the query carries them, and every
            argument by name with the defaults applied.

        Raises:
            TypeError: If the arguments do not match the signature.
        """
        bound = self.__signature__.bind(*args, **kwargs)
        bound.apply_defaults()
        values = dict(bound.arguments)
        route = self._route
        filters = {
            option.name: wire(
                values[python_name(option.name)], repeatable=option.repeatable
            )
            for option in route.options
        }
        positional = str(values[route.positional]) if route.positional else ""
        return positional, filters, values


def _accepted(answer: Answer, values: dict[str, Any]) -> Any:
    """Hand back an answer, unless it is incomplete and that was not accepted.

    Args:
        answer: What the route returned.
        values: The call's arguments, with ``allow_incomplete`` when the
            route takes it.

    Returns:
        The answer's result.

    Raises:
        IncompleteAnswer: If the API reported rows it could not resolve and
            ``allow_incomplete`` was not set.
    """
    if answer.missing and not values.get("allow_incomplete", False):
        raise IncompleteAnswer(
            "The API could not resolve every row: "
            + "; ".join(answer.missing)
            + ". Pass allow_incomplete=True to accept the partial answer.",
            result=answer.result,
            envelope=answer.envelope,
        )
    return answer.result


class Group:
    """A command group, holding its subcommands as attributes.

    Args:
        command: The words that select this group, after the program name.
    """

    def __init__(self, command: tuple[str, ...]) -> None:
        self._command = command

    def __repr__(self) -> str:
        """List what the group holds.

        Returns:
            For example ``<threatmodels: actions, controls, dfd, get, list>``.
        """
        names = sorted(name for name in vars(self) if not name.startswith("_"))
        return f"<{'.'.join(self._command)}: {', '.join(names)}>"


class Client(TocClient):
    """A TrustOnCloud API client whose attributes mirror the CLI's commands.

    Credentials resolve exactly as the CLI's do, so a key that works with
    ``tmxcaliber me`` works here with no arguments: ``TOC_API_KEY``, then
    ``~/.trustoncloud/credentials``, with the endpoint resolved separately
    from ``TOC_API_URL``, the file, or the default. An argument wins over
    both.

    ``get`` and ``paginate`` stay available for a raw path.

    Args:
        api_key: A key to use instead of the environment's or the file's.
        api_url: An endpoint to use instead of the environment's or the
            file's.
        contract: ``"vendored"`` builds the methods from the contract this
            release ships with, at no cost. ``"live"`` reads the API's own
            definition for this credential first, two calls on every
            construction, so routes this tenant has before every tenant
            does, such as ``overwatch``, are methods too; reuse the client.
        timeout: Seconds to wait on one request.
        opener: The URL opener, injected so a test needs no network.

    Raises:
        ValueError: If ``contract`` is not one of the names above.
        ConfigurationError: If no usable credential is configured.
        ContractViolation: If the live definition cannot be read or bound
            by this release.
        RemoteError: On any other failure reading the live definition.

    Warns:
        UserWarning: When a key given for this call will reach an endpoint
            stored in the credentials file, which is easy to miss.
    """

    def __init__(
        self,
        api_key: str = "",
        api_url: str = "",
        *,
        contract: ContractName = "vendored",
        timeout: float = DEFAULT_TIMEOUT,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        # Checked first, so a misspelling needs no credential and spends no call.
        if contract not in CONTRACT_NAMES:
            raise ValueError(
                f"contract must be one of {', '.join(CONTRACT_NAMES)}, "
                f"not {contract!r}."
            )
        settings = load_settings(api_key=api_key, api_url=api_url, timeout=timeout)
        if settings.sends_key_to_stored_endpoint:
            warnings.warn(settings.stored_endpoint_note, stacklevel=2)
        super().__init__(settings, opener=opener)
        # Held by this client alone, so two clients built from different
        # contracts in one process never see each other's routes.
        self._contract = (
            vendored() if contract == "vendored" else load_live_contract(self)
        )
        try:
            for route in self._contract.routes:
                self._attach(route)
        except ValueError as exc:
            if not self._contract.live:
                raise
            raise live_refusal(exc) from exc

    def _attach(self, route: Route) -> None:
        """Hang one route's operation at its command's attribute path.

        Args:
            route: The route.

        Raises:
            ValueError: If a command word would hide a client attribute, or a
                group and an operation would share a name. Tests build a
                client over the vendored contract with every marked route
                unlocked, so this fires in CI rather than for a caller, unless
                a live definition is newer than this release.
        """
        holder: object = self
        for depth, word in enumerate(route.command[:-1]):
            child = getattr(holder, word, None)
            if child is None:
                self._refuse_shadowing(holder, word, route)
                child = Group(route.command[: depth + 1])
                setattr(holder, word, child)
            if not isinstance(child, Group):
                raise ValueError(f"{route.path}: {word!r} is not a command group.")
            holder = child
        leaf = route.command[-1]
        self._refuse_shadowing(holder, leaf, route)
        setattr(holder, leaf, Operation(self, route))

    @staticmethod
    def _refuse_shadowing(holder: object, word: str, route: Route) -> None:
        """Refuse a command word that already names something on its holder.

        Args:
            holder: The client or group the word would be set on.
            word: The command word.
            route: The route, for the message.

        Raises:
            ValueError: If ``word`` is already an attribute of ``holder``.
        """
        if hasattr(holder, word):
            raise ValueError(
                f"{route.path}: the command word {word!r} is already taken "
                f"on {type(holder).__name__}."
            )

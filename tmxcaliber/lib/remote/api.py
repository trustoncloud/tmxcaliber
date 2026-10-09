"""The TrustOnCloud API as a Python object, shaped like the CLI.

Every attribute path on a `Client` is a CLI command with the spaces turned
into dots, built at construction from the same route table the CLI is built
from (`contract.ROUTES`). Nothing here names a route, so a route the API adds
is a method here and a command there, with no naming decision in between:

    from tmxcaliber import Client

    api = Client()                         # tmxcaliber me
    api.me()
    api.threatmodels.list(provider="aws")  # tmxcaliber threatmodels list --provider aws
    api.threatmodels.threats("aws-s3", feature_class="S3.FC1")

A route's positional is the method's one positional argument, its filters are
keyword arguments, and a paged route returns every row, as the CLI does.
"""

from __future__ import annotations

import inspect
import urllib.request
import warnings
from typing import Any

from .client import TocClient
from .config import DEFAULT_TIMEOUT, load_settings
from .contract import ROUTES, Route, required_parameters
from .errors import IncompleteAnswer
from .operations import call_route, incompleteness_fields


def _signature(route: Route) -> inspect.Signature:
    """Describe the call that reaches a route, the way its CLI command reads.

    Args:
        route: The route.

    Returns:
        A positional-only parameter for the route's positional, a keyword-only
        one per filter (without a default when the API requires it), then
        ``limit`` for a paged route and ``allow_incomplete`` for a route whose
        pages can report missing rows.
    """
    keyword = inspect.Parameter.KEYWORD_ONLY
    required = required_parameters(route.path)
    parameters = [
        inspect.Parameter(name, keyword, default=inspect.Parameter.empty)
        if name in required
        else inspect.Parameter(name, keyword, default=None)
        for name in route.filters
    ]
    if route.positional:
        parameters.insert(
            0, inspect.Parameter(route.positional, inspect.Parameter.POSITIONAL_ONLY)
        )
    if route.paged:
        parameters.append(inspect.Parameter("limit", keyword, default=0))
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
            **kwargs: The route's filters, ``limit`` and ``allow_incomplete``,
                as the signature lists them.

        Returns:
            Every row of a paged route, or the object any other route returns.

        Raises:
            TypeError: If the arguments do not match the signature.
            IncompleteAnswer: If the API reported rows it could not resolve
                and ``allow_incomplete`` was not set.
            RemoteError: On any credential, transport or server failure.
            ValueError: If a ThreatModel reference cannot be parsed.
        """
        bound = self.__signature__.bind(*args, **kwargs)
        bound.apply_defaults()
        values = bound.arguments
        route = self._route
        answer = call_route(
            self._client,
            route,
            str(values[route.positional]) if route.positional else "",
            {
                name: "" if values[name] is None else str(values[name])
                for name in route.filters
            },
            limit=int(values.get("limit", 0)),
        )
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
        timeout: Seconds to wait on one request.
        opener: The URL opener, injected so a test needs no network.

    Raises:
        ConfigurationError: If no usable credential is configured.

    Warns:
        UserWarning: When a key given for this call will reach an endpoint
            stored in the credentials file, which is easy to miss.
    """

    def __init__(
        self,
        api_key: str = "",
        api_url: str = "",
        *,
        timeout: float = DEFAULT_TIMEOUT,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        settings = load_settings(api_key=api_key, api_url=api_url, timeout=timeout)
        if settings.sends_key_to_stored_endpoint:
            warnings.warn(settings.stored_endpoint_note, stacklevel=2)
        super().__init__(settings, opener=opener)
        for route in ROUTES:
            self._attach(route)

    def _attach(self, route: Route) -> None:
        """Hang one route's operation at its command's attribute path.

        Args:
            route: The route.

        Raises:
            ValueError: If a command word would hide a client attribute, or a
                group and an operation would share a name. The route table
                is checked by a test, so this fires in CI rather than for a
                caller.
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

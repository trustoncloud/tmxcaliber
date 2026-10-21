"""Exceptions for the TrustOnCloud API client.

One class per error code the API publishes, so a caller can branch on the
failure rather than on a string. The codes themselves are owned by the API
(`app/containers/public-api/src/errors.ts`); this module maps them and adds
three local failures the server never sends.

Every message carries the server's `requestId` when there is one, because the
API's own contract is that a caller quotes it to support.
"""

from __future__ import annotations

from typing import Any


class RemoteError(Exception):
    """A call to the TrustOnCloud API did not succeed.

    Args:
        message: What went wrong, in the server's words where there are any.
        code: The API's error code, or a local code for a client-side failure.
        request_id: The server-generated request identifier, when one arrived.
        status: The HTTP status, when the failure reached one.
        did_you_mean: A sentence that names what the caller probably meant,
            such as ``Did you mean aws-ec2?``, with anything said about it,
            or empty when nothing is close. It is kept apart from the message
            so the command line can set it on a line of its own, while
            ``str()`` still reads as one line.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "",
        request_id: str | None = None,
        status: int | None = None,
        did_you_mean: str = "",
    ) -> None:
        self.code = code
        self.request_id = request_id
        self.status = status
        self.did_you_mean = did_you_mean
        super().__init__(message)

    @property
    def headline(self) -> str:
        """Render the failure without its suggestion.

        Returns:
            The message, followed by the request id when the server sent one,
            for a printer that writes ``did_you_mean`` after it on its own.
        """
        return self._render("")

    def __str__(self) -> str:
        """Render the failure with the identifier support will ask for.

        Returns:
            The message, then ``did_you_mean`` as a sentence of its own when
            there is one, then the request id when the server sent one.
        """
        return self._render(self.did_you_mean)

    def _render(self, did_you_mean: str) -> str:
        """Render the message, a suggestion when given, and the request id.

        Args:
            did_you_mean: The suggestion to follow the message, or empty.

        Returns:
            The text. A full stop is put between a message that has none and
            the suggestion, which would otherwise run the two sentences
            together, and none after a message that already ends a sentence.
        """
        base = super().__str__()
        if did_you_mean:
            stop = "" if not base or base.endswith((".", "!", "?")) else "."
            base = f"{base}{stop} {did_you_mean}".strip()
        if self.request_id:
            return f"{base} (request {self.request_id})"
        return base


class AuthenticationError(RemoteError):
    """The credential was missing, malformed, unknown, revoked or expired."""


class AddressNotAllowed(RemoteError):
    """The caller's address is not on the tenant's allow list.

    Deny is the default on that list, so this is equally what an unconfigured
    tenant and an IPv6 caller receive.
    """


class PermissionDenied(RemoteError):
    """The credential is valid but does not carry the route's permission."""


class NotFound(RemoteError):
    """No such ThreatModel, release or pack, as far as this caller can tell.

    The API answers the same way for a model that does not exist, one the
    tenant is not entitled to, and every route of a tenant whose organization
    has no access to the API at all. They are deliberately indistinguishable,
    so a message that guessed between them would mislead.
    """


class ReleaseSuperseded(RemoteError):
    """The release a read was pinned to is no longer the one published.

    The API serves only a pack's current release. A pin naming any other,
    because the pack was republished or rolled back between two reads, is
    refused rather than answered from a different release, so the caller can
    read the manifest again and retry.
    """


class InvalidRequest(RemoteError):
    """The server refused a parameter."""


class InvalidCursor(InvalidRequest):
    """A page cursor was rejected.

    Cursors are bound to the credential, the route and the filters, so this
    is what a key rotation part-way through a walk produces.
    """


class RateLimited(RemoteError):
    """A rate limit was reached.

    Args:
        message: The server's explanation.
        retry_after: Seconds the server asked the caller to wait, when it said.
        code: The API's error code.
        request_id: The server-generated request identifier.
        status: The HTTP status.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        code: str = "",
        request_id: str | None = None,
        status: int | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(message, code=code, request_id=request_id, status=status)


class ServiceUnavailable(RemoteError):
    """The API could not answer, and the failure is the platform's."""


class ContractViolation(RemoteError):
    """The server answered in a shape the contract does not allow.

    Local rather than served. It covers a body that is not JSON, a page that
    is missing its envelope, and a cursor walk that does not terminate.
    """


class ConfigurationError(RemoteError):
    """No usable credential was found, so no call was attempted."""


class IncompleteAnswer(RemoteError):
    """The API answered, and said the answer is missing rows.

    Local rather than served: the call succeeded, and its page named rows it
    could not resolve. Raised so a caller cannot take a partial collection
    for a whole one; the rows it did get travel with it.

    Args:
        message: Which fields reported missing rows, and their values.
        result: The rows the API did return.
        envelope: The page's fields other than the paging ones.
    """

    def __init__(
        self,
        message: str,
        *,
        result: list[dict[str, Any]],
        envelope: dict[str, Any],
    ) -> None:
        super().__init__(message, code="incomplete")
        self.result = result
        self.envelope = envelope


#: Each published error code, mapped to the class that carries it.
#:
#: Owned by the API; a code absent from here is still raised, as the base
#: ``RemoteError``, rather than being swallowed.
BY_CODE: dict[str, type[RemoteError]] = {
    "invalid_credential": AuthenticationError,
    "ip_not_allowed": AddressNotAllowed,
    "forbidden": PermissionDenied,
    "not_found": NotFound,
    "release_superseded": ReleaseSuperseded,
    "invalid_request": InvalidRequest,
    "invalid_cursor": InvalidCursor,
    "rate_limited": RateLimited,
    "unavailable": ServiceUnavailable,
}


#: The failure classes a bare HTTP status maps to, when no envelope arrived.
#:
#: A status without the API's error envelope means something other than the
#: application answered, which a distribution in front of the origin makes
#: entirely possible.
BY_STATUS: dict[int, type[RemoteError]] = {
    401: AuthenticationError,
    403: PermissionDenied,
    404: NotFound,
    410: ReleaseSuperseded,
    400: InvalidRequest,
    429: RateLimited,
    500: ServiceUnavailable,
    502: ServiceUnavailable,
    503: ServiceUnavailable,
    504: ServiceUnavailable,
}

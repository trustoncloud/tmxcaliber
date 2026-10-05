"""Exceptions for the TrustOnCloud API client.

One class per error code the API publishes, so a caller can branch on the
failure rather than on a string. The codes themselves are owned by the API
(`app/containers/public-api/src/errors.ts`); this module maps them and adds
two local failures the server never sends.

Every message carries the server's `requestId` when there is one, because the
API's own contract is that a caller quotes it to support.
"""

from __future__ import annotations


class RemoteError(Exception):
    """A call to the TrustOnCloud API did not succeed.

    Args:
        message: What went wrong, in the server's words where there are any.
        code: The API's error code, or a local code for a client-side failure.
        request_id: The server-generated request identifier, when one arrived.
        status: The HTTP status, when the failure reached one.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "",
        request_id: str | None = None,
        status: int | None = None,
    ) -> None:
        self.code = code
        self.request_id = request_id
        self.status = status
        super().__init__(message)

    def __str__(self) -> str:
        """Render the failure with the identifier support will ask for.

        Returns:
            The message, followed by the request id when the server sent one.
        """
        base = super().__str__()
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


#: Each published error code, mapped to the class that carries it.
#:
#: Owned by the API; a code absent from here is still raised, as the base
#: ``RemoteError``, rather than being swallowed.
BY_CODE: dict[str, type[RemoteError]] = {
    "invalid_credential": AuthenticationError,
    "ip_not_allowed": AddressNotAllowed,
    "forbidden": PermissionDenied,
    "not_found": NotFound,
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
    400: InvalidRequest,
    429: RateLimited,
    500: ServiceUnavailable,
    502: ServiceUnavailable,
    503: ServiceUnavailable,
    504: ServiceUnavailable,
}

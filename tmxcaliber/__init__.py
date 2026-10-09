"""Refine TrustOnCloud ThreatModels, and read them from the TrustOnCloud API.

The library's public surface is the API client and the errors it raises:

    from tmxcaliber import Client

    api = Client()
    api.threatmodels.threats("aws-s3", feature_class="S3.FC1")

Everything else in the package backs the ``tmxcaliber`` command and may move
between releases.
"""

from .lib.remote import (
    AddressNotAllowed,
    AuthenticationError,
    Client,
    ConfigurationError,
    ContractViolation,
    IncompleteAnswer,
    InvalidCursor,
    InvalidRequest,
    NotFound,
    PermissionDenied,
    RateLimited,
    RemoteError,
    ServiceUnavailable,
)

__all__ = [
    "AddressNotAllowed",
    "AuthenticationError",
    "Client",
    "ConfigurationError",
    "ContractViolation",
    "IncompleteAnswer",
    "InvalidCursor",
    "InvalidRequest",
    "NotFound",
    "PermissionDenied",
    "RateLimited",
    "RemoteError",
    "ServiceUnavailable",
]

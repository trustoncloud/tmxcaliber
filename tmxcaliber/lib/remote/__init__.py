"""Read ThreatModels from the TrustOnCloud API.

The public surface of this subpackage. Everything a command needs is
re-exported here so the modules underneath stay free to move.

Nothing in here runs until a command asks for a remote source, so a caller
working on local files is never asked for a credential.
"""

from __future__ import annotations

from .assemble import fetch_document, load_remote
from .client import TocClient
from .config import Credentials, Settings, load_settings
from .contract import ROUTES, Route, route_for
from .errors import (
    AddressNotAllowed,
    AuthenticationError,
    ConfigurationError,
    ContractViolation,
    InvalidCursor,
    InvalidRequest,
    NotFound,
    PermissionDenied,
    RateLimited,
    RemoteError,
    ServiceUnavailable,
)
from .ref import TmRef, is_remote_ref, parse_ref
from .resolve import fetch_to_cache, resolve_source

__all__ = [
    "ROUTES",
    "AddressNotAllowed",
    "AuthenticationError",
    "ConfigurationError",
    "ContractViolation",
    "Credentials",
    "InvalidCursor",
    "InvalidRequest",
    "NotFound",
    "PermissionDenied",
    "RateLimited",
    "RemoteError",
    "Route",
    "ServiceUnavailable",
    "Settings",
    "TmRef",
    "TocClient",
    "fetch_document",
    "fetch_to_cache",
    "is_remote_ref",
    "load_remote",
    "load_settings",
    "parse_ref",
    "resolve_source",
    "route_for",
]

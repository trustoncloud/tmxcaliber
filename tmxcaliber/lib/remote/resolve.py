"""Turn a command's source argument into a path on disk.

Every document command takes a source where a filename used to be the only
possibility. A reference such as ``aws-s3`` now works in the same slot: it
is fetched, cached, and the cache path is handed back, so nothing further
down the command has to know where the document came from.

**Disk wins.** A value that exists on disk is a path, always. A value that
does not exist and matches the reference grammar is a reference. Anything
else raises exactly the error it raised before. That ordering is what keeps
every existing invocation meaning what it meant.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from .assemble import fetch_document
from .cache import DEFAULT_MAX_AGE, PINNED_MAX_AGE, cached_path, read, write
from .client import TocClient
from .config import load_settings
from .ref import TmRef, is_remote_ref, parse_ref


def _client(env: Mapping[str, str] | None = None) -> TocClient:
    """Build a client, resolving the credential only now.

    Args:
        env: The environment to read.

    Returns:
        The client.

    Raises:
        ConfigurationError: If no usable credential is configured.
    """
    return TocClient(load_settings(env=env))


def fetch_to_cache(
    ref: TmRef,
    *,
    client: TocClient | None = None,
    refresh: bool = False,
    env: Mapping[str, str] | None = None,
) -> str:
    """Fetch one ThreatModel and return the path it was cached at.

    A pinned release is immutable, so a cached copy of one is good forever.
    An unpinned reference is kept under its own name with a lifetime,
    because what "latest" means can change; within that lifetime a repeated
    reference costs no calls at all, which matters against an hourly budget
    that a single assembly spends five of.

    Args:
        ref: The ThreatModel, optionally pinned to a release.
        client: A client to use, built from the environment when omitted.
        refresh: Fetch even when a cached copy would do.
        env: The environment to read.

    Returns:
        The path to the cached document.

    Raises:
        RemoteError: On any transport, credential or server failure.
    """
    api = client or _client(env)

    if ref.release:
        path = cached_path(ref, ref.release, api.base_url, api.key_id, env)
        if not refresh and read(path, max_age=PINNED_MAX_AGE) is not None:
            return str(path)
        write(path, fetch_document(api, ref).document)
        return str(path)

    latest = cached_path(ref, "latest", api.base_url, api.key_id, env)
    if not refresh and read(latest, max_age=DEFAULT_MAX_AGE) is not None:
        return str(latest)

    fetched = fetch_document(api, ref)
    write(latest, fetched.document)
    # Also stored under the release it turned out to be, so a later pinned
    # reference to the same version is served without a call. Keyed from
    # the API's release and never from `metadata.version`, which is the
    # template schema date and would file every model under the same name.
    if fetched.release:
        write(
            cached_path(ref, fetched.release, api.base_url, api.key_id, env),
            fetched.document,
        )
    return str(latest)


def resolve_source(
    source: str,
    *,
    client: TocClient | None = None,
    refresh: bool = False,
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve a command's source to a path on disk.

    Args:
        source: A filesystem path, a directory, or a ThreatModel reference.
        client: A client to use, built from the environment when omitted.
        refresh: Fetch even when a cached copy would do.
        env: The environment to read.

    Returns:
        A path. The input unchanged when it was already one.

    Raises:
        RemoteError: On any transport, credential or server failure.

    Example:
        >>> resolve_source("./threatmodel.json")
        './threatmodel.json'
    """
    if os.path.exists(source):
        return source
    if not is_remote_ref(source):
        # Not a path and not a reference. Left exactly as it came, so the
        # caller's own validation produces the message it always produced.
        return source
    return fetch_to_cache(parse_ref(source), client=client, refresh=refresh, env=env)

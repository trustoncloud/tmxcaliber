"""On-disk cache for assembled ThreatModel documents.

Separate from `lib/cache.py`, which serves the SCF workbooks, and
deliberately so. That cache keys on the last segment of a URL, which would
collide for every model's subresources; it treats "the file exists" as
"the file is complete", so an interrupted download becomes a permanent
poisoned hit; and changing it would change `lib/scf.py`, which sits in the
dependency path of other repositories and deserves its own change.

The documents here are licensed artifacts carrying a per-tenant attribution,
so the cache lives under the user's own home at mode 0700 rather than in a
world-readable temporary directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import time
from collections.abc import Mapping
from typing import Any

from .ref import TmRef

#: How long an assembled document is reused when no release was pinned.
#:
#: A pinned release is immutable, so it never expires. Only the meaning of
#: "latest" can change underneath a caller.
DEFAULT_MAX_AGE = 24 * 60 * 60.0


def cache_root(env: Mapping[str, str] | None = None) -> pathlib.Path:
    """Resolve the cache directory.

    Args:
        env: The environment to read, defaulting to the real one.

    Returns:
        The directory, which may not exist yet.
    """
    environ = os.environ if env is None else env
    override = environ.get("TMXCALIBER_CACHE_DIR")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".tmxcaliber" / "cache"


def cached_path(
    ref: TmRef, release: str, base_url: str, env: Mapping[str, str] | None = None
) -> pathlib.Path:
    """Work out where one document is cached.

    The base URL is part of the key, so a staging endpoint and production
    can never serve each other's documents out of one cache.

    Args:
        ref: The ThreatModel.
        release: The resolved release key, never empty.
        base_url: The API this document came from.
        env: The environment to read.

    Returns:
        The file path.
    """
    endpoint = hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:12]
    return cache_root(env) / endpoint / ref.tm_id / f"{release}.json"


def read(
    path: pathlib.Path, *, max_age: float | None = DEFAULT_MAX_AGE
) -> dict[str, Any] | None:
    """Read a cached document, if one is present and fresh enough.

    Args:
        path: Where the document would be.
        max_age: Seconds before a cached document is considered stale, or
            None to accept it whatever its age.

    Returns:
        The document, or None when absent, stale or unreadable.
    """
    try:
        if max_age is not None and time.time() - path.stat().st_mtime > max_age:
            return None
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # A damaged cache entry is a cache miss. It is never an error worth
        # stopping for, because the document can always be fetched again.
        return None
    return loaded if isinstance(loaded, dict) else None


def write(path: pathlib.Path, document: Mapping[str, Any]) -> pathlib.Path:
    """Store a document, atomically.

    Written to a temporary file in the same directory and then renamed, so
    an interrupted write leaves no half-document for a later read to treat
    as a hit.

    Args:
        path: Where to store it.
        document: The document.

    Returns:
        The path written.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), suffix=".part")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(document, out)
        os.replace(temporary, path)
    except BaseException:
        pathlib.Path(temporary).unlink(missing_ok=True)
        raise
    return path

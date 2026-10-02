"""Where the API credential and endpoint come from.

A TrustOnCloud API key is not a tmxcaliber credential. The same key works
with curl, with an SDK, or with anything else that speaks to the API, so it
is named and stored for TrustOnCloud rather than for this tool: ``TOC_``
environment variables and ``~/.trustoncloud/``. tmxcaliber's own artifacts,
such as its document cache, stay under ``TMXCALIBER_`` and ``~/.tmxcaliber/``.

Resolution is lazy on purpose. A caller operating on a local file must never
be asked for a credential, so nothing here runs until a command actually
needs to reach the API.
"""

from __future__ import annotations

import configparser
import os
import pathlib
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .errors import ConfigurationError

#: The API this client talks to, unless an environment or profile says otherwise.
DEFAULT_BASE_URL: Final[str] = "https://api.trustoncloud.com"

#: Seconds to wait on a single request before giving up.
#:
#: `lib/cache.py` sets no timeout at all, which is the mistake not to repeat:
#: a stalled connection there hangs the command with no output and no end.
DEFAULT_TIMEOUT: Final[float] = 30.0

#: The shape of a tenant API key.
#:
#: **A knowing second copy of a fact another repository owns**
#: (`app/containers/shared/src/apiKeyFormat.ts`). There is no cross-boundary
#: way to share it, and checking locally turns a typo into an instant message
#: rather than a 401 that also spends one of the sixty failed authentications
#: per minute the API allows a source address.
CREDENTIAL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^toc-(?:tak1|uak1)-[0-9A-HJKMNP-TV-Z]{16}-[0-9A-HJKMNP-TV-Z]{52}$"
)

_HELP = """No TrustOnCloud API key found.

Set TOC_API_KEY, or add one to ~/.trustoncloud/credentials:

  [default]
  api_key = toc-tak1-...

Create a key in the app under Settings, Service API keys. Your organization
must have IP filtering configured first, and the address you run from has to
be on the allow list."""


@dataclass(frozen=True, repr=False)
class Credentials:
    """An API key and a note of where it was found.

    ``repr`` is hand-written and omits the key, so the secret cannot reach a
    traceback frame or a pytest assertion dump.

    Attributes:
        api_key: The tenant API key.
        source: Where it came from, for diagnostics. Never the key itself.
    """

    api_key: str
    source: str

    def __repr__(self) -> str:
        """Describe the credential without disclosing it.

        Returns:
            The source only.
        """
        return f"Credentials(source={self.source!r})"

    @property
    def key_id(self) -> str:
        """The credential's public identifier.

        A key is ``toc-<kind>-<id>-<secret>``, and only the last part is a
        secret. The id names which credential is asking, which is what the
        cache needs in order not to serve one tenant's document to another.

        Returns:
            The key id, or an empty string if the key is not in that shape.
        """
        parts = self.api_key.split("-")
        return parts[2] if len(parts) >= 4 else ""


@dataclass(frozen=True)
class Settings:
    """Everything needed to reach the API.

    Attributes:
        credentials: The resolved API key.
        base_url: The API root, without a trailing slash.
        timeout: Seconds to wait on one request.
    """

    credentials: Credentials
    base_url: str = DEFAULT_BASE_URL
    timeout: float = DEFAULT_TIMEOUT


def config_path(env: Mapping[str, str]) -> pathlib.Path:
    """Resolve the credentials file location.

    Resolved on call rather than at import, so a test can redirect it and so
    ``params.py``'s import-time ``os.getcwd()`` is not repeated here.

    Args:
        env: The environment to read.

    Returns:
        The path to the credentials file, whether or not it exists.
    """
    override = env.get("TOC_CONFIG_FILE")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".trustoncloud" / "credentials"


def _from_file(
    env: Mapping[str, str], profile: str | None
) -> tuple[str, str, str] | None:
    """Read a key and base URL from the credentials file.

    Args:
        env: The environment to read.
        profile: The section to use, or None for the default.

    Returns:
        The key, the base URL (empty when unset) and a source note, or None
        when the file or the section is absent.

    Raises:
        ConfigurationError: If the file exists but cannot be parsed.
    """
    path = config_path(env)
    if not path.is_file():
        return None
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as exc:
        raise ConfigurationError(
            f"{path} could not be read: {exc}", code="bad_config"
        ) from None
    section = profile or env.get("TOC_PROFILE") or "default"
    if not parser.has_section(section):
        return None
    key = parser.get(section, "api_key", fallback="").strip()
    if not key:
        return None
    url = parser.get(section, "api_url", fallback="").strip()
    return key, url, f"{path}#{section}"


def load_settings(
    *,
    profile: str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Settings:
    """Resolve the credential and endpoint.

    The environment wins over the file, so a one-off override needs no edit.

    Args:
        profile: The credentials-file section, or None for ``TOC_PROFILE``
            and then ``default``.
        env: The environment to read, defaulting to the real one.
        timeout: Seconds to wait on one request.

    Returns:
        The resolved settings.

    Raises:
        ConfigurationError: If no key is configured, or one is malformed.
    """
    environ = os.environ if env is None else env

    key = environ.get("TOC_API_KEY", "").strip()
    source = "TOC_API_KEY"
    url = environ.get("TOC_API_URL", "").strip()

    if not key:
        found = _from_file(environ, profile)
        if found is None:
            raise ConfigurationError(_HELP, code="no_credential")
        key, file_url, source = found
        url = url or file_url

    if CREDENTIAL_PATTERN.match(key) is None:
        # Named without quoting it. A malformed key in an error message is
        # still a secret if it was only mistyped by one character.
        raise ConfigurationError(
            f"The API key from {source} is not a TrustOnCloud key. "
            "A key looks like toc-tak1- followed by an id and a secret.",
            code="bad_credential",
        )

    base_url = (url or DEFAULT_BASE_URL).rstrip("/")
    _refuse_cleartext(base_url)

    return Settings(
        credentials=Credentials(api_key=key, source=source),
        base_url=base_url,
        timeout=timeout,
    )


#: Hosts a plain-HTTP endpoint is tolerated on.
#:
#: Only the loopback interface, where the connection never leaves the
#: machine. Everything else must be HTTPS, because the key travels in a
#: request header and a mistyped or untrusted endpoint would otherwise read
#: it off the wire.
LOOPBACK: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _refuse_cleartext(base_url: str) -> None:
    """Refuse an endpoint that would carry the credential in the clear.

    Args:
        base_url: The resolved API root.

    Raises:
        ConfigurationError: If the endpoint is neither HTTPS nor loopback.
    """
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in LOOPBACK:
        return
    raise ConfigurationError(
        f"{base_url} is not an https endpoint. The API key travels in a "
        "request header, so only https, or http on localhost for local "
        "development, is accepted.",
        code="insecure_endpoint",
    )

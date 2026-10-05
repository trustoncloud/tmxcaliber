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
import tempfile
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .errors import ConfigurationError

#: The API this client talks to, unless the environment or the file says otherwise.
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


#: The one section the credentials file has.
#:
#: There are no profiles. One key, one endpoint, and `TOC_API_KEY` for the
#: "a different one, right now" case, which is what an environment variable
#: is good at. A profile mechanism would be a second way to say the same
#: thing and a second thing for `init` to keep straight.
SECTION: Final[str] = "default"


def _refuse_shared_file(path: pathlib.Path) -> None:
    """Refuse a credentials file other local users can read.

    The CLI writes this file at 0600, so a wider mode means it was created
    by hand under a default umask, or loosened since. Either way the key is
    readable by every other account on the machine.

    Args:
        path: The credentials file.

    Raises:
        ConfigurationError: If the file is group or world accessible.
    """
    if os.name != "posix":
        # Windows has no mode bits worth reading here, and guessing at an
        # ACL would refuse working setups.
        return
    mode = path.stat().st_mode & 0o077
    if mode:
        raise ConfigurationError(
            f"{path} is readable by other users on this machine "
            f"(mode {oct(path.stat().st_mode & 0o777)}). Run `tmxcaliber "
            "init` to rewrite it, or `chmod 600` it yourself.",
            code="exposed_credential",
        )


def _from_file(env: Mapping[str, str]) -> tuple[str, str, str] | None:
    """Read the key and base URL from the credentials file.

    Args:
        env: The environment to read.

    Returns:
        The key, the base URL (empty when unset) and a source note, or None
        when the file is absent or holds no key.

    Raises:
        ConfigurationError: If the file cannot be parsed, or other users can
            read it.
    """
    path = config_path(env)
    if not path.is_file():
        return None
    _refuse_shared_file(path)
    # **Interpolation off.** With it on, a `%` anywhere in a value raises an
    # InterpolationSyntaxError whose message quotes the rest of that value,
    # so a mangled key would be disclosed by the error complaining about it.
    # A credentials file has nothing to interpolate.
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
        if not parser.has_section(SECTION):
            return None
        key = parser.get(SECTION, "api_key", fallback="").strip()
        url = parser.get(SECTION, "api_url", fallback="").strip()
    except configparser.Error as exc:
        # **The message never carries the parser's text.** ConfigParser puts
        # the offending line into a ParsingError, so a key written without
        # its separator would be printed to a terminal or a CI log by the
        # very error that complained about it. A line number says as much
        # as the reader needs and discloses nothing.
        where = ""
        errors = getattr(exc, "errors", None)
        if errors:
            where = f" at line {errors[0][0]}"
        raise ConfigurationError(
            f"{path} could not be parsed as an INI file{where}.",
            code="bad_config",
        ) from None
    if not key:
        return None
    return key, url, str(path)


def masked(api_key: str) -> str:
    """Render a key with its secret hidden.

    The key id is public and is what support asks for, so it stays legible;
    the secret never does.

    Args:
        api_key: The key.

    Returns:
        The key with its last part replaced.
    """
    parts = api_key.split("-")
    if len(parts) < 4:
        return "(not a TrustOnCloud key)"
    return "-".join([*parts[:3], "*" * 8])


def write_credentials(
    api_key: str, *, api_url: str = "", env: Mapping[str, str] | None = None
) -> pathlib.Path:
    """Write the credentials file, readable only by its owner.

    **The CLI writes this file so that it owns the mode.** Telling a user to
    create it by hand means a default umask decides who can read a tenant
    credential, and the README cannot enforce a `chmod`.

    Args:
        api_key: The key to store.
        api_url: An endpoint to store, or empty for the default.
        env: The environment to read.

    Returns:
        The path written.

    Raises:
        ConfigurationError: If the key is not a TrustOnCloud key.
    """
    if CREDENTIAL_PATTERN.match(api_key) is None:
        raise ConfigurationError(
            "That is not a TrustOnCloud key. A key looks like toc-tak1- "
            "followed by an id and a secret.",
            code="bad_credential",
        )
    path = config_path(os.environ if env is None else env)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    body = f"[{SECTION}]\napi_key = {api_key}\n"
    if api_url:
        body += f"api_url = {api_url}\n"

    # Written to a temporary file in the same directory and renamed, with
    # the mode set before anything is in it, so the key is never briefly
    # readable by anyone else.
    handle, temporary = tempfile.mkstemp(dir=str(path.parent))
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(body)
        os.replace(temporary, path)
    except BaseException:
        pathlib.Path(temporary).unlink(missing_ok=True)
        raise
    return path


def load_settings(
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Settings:
    """Resolve the credential and endpoint.

    The environment wins over the file, so a one-off override needs no edit
    and no profile.

    Args:
        env: The environment to read, defaulting to the real one.
        timeout: Seconds to wait on one request.

    Returns:
        The resolved settings.

    Raises:
        ConfigurationError: If no key is configured, or one is malformed.
    """
    environ = os.environ if env is None else env

    # **The endpoint is resolved independently of the key.** Reading the
    # file only when the key was absent meant that setting TOC_API_KEY
    # silently moved a configured custom endpoint back to the default, so
    # a caller could verify one API and then call another.
    stored = _from_file(environ)
    url = environ.get("TOC_API_URL", "").strip() or (stored[1] if stored else "")

    key = environ.get("TOC_API_KEY", "").strip()
    source = "TOC_API_KEY"
    if not key:
        if stored is None:
            raise ConfigurationError(_HELP, code="no_credential")
        key, _, source = stored

    return settings_for(key, api_url=url, source=source, timeout=timeout)


def settings_for(
    api_key: str,
    *,
    api_url: str = "",
    source: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> Settings:
    """Build settings from a credential given explicitly.

    **The one place a key and an endpoint become usable settings**, so the
    format and scheme rules cannot be skipped by a caller that assembles a
    `Settings` itself. `init` uses it to verify the credential it just
    stored rather than whatever ambient resolution would pick.

    Args:
        api_key: The key.
        api_url: The endpoint, or empty for the default.
        source: Where the key came from, for diagnostics.
        timeout: Seconds to wait on one request.

    Returns:
        The settings.

    Raises:
        ConfigurationError: If the key is malformed, or the endpoint would
            carry it in the clear.
    """
    if CREDENTIAL_PATTERN.match(api_key) is None:
        # Named without quoting it. A malformed key in an error message is
        # still a secret if it was only mistyped by one character.
        raise ConfigurationError(
            f"The API key from {source or 'input'} is not a TrustOnCloud key. "
            "A key looks like toc-tak1- followed by an id and a secret.",
            code="bad_credential",
        )
    base_url = (api_url or DEFAULT_BASE_URL).rstrip("/")
    _refuse_cleartext(base_url)
    return Settings(
        credentials=Credentials(api_key=api_key, source=source),
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

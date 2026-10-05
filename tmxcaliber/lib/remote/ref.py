"""The identifier a command accepts in place of a file path.

A ThreatModel is named by its ``tmId``, which is what the API's catalogue
returns, so a row of ``tmxcaliber threatmodels list`` output pastes straight
into the next command. An optional ``@release`` pins a version.

    aws-s3
    aws-s3@1611187200

The URL wants the two halves as separate path segments, so the id splits on
its **first** hyphen only. Every one of the 264 published models currently
carries exactly one hyphen, because service names are collapsed
(``aws-apigatewayv2``, ``aws-acmpca``) rather than hyphenated, but nothing
enforces that and a single split costs nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: A ThreatModel id, optionally pinned to a release.
#:
#: Deliberately narrow. This pattern decides whether a source that is not on
#: disk is a remote reference or a typo, so anything it accepts that was meant
#: to be a filename becomes a confusing network error instead of the
#: filesystem message the caller expected.
REF_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<provider>[a-z0-9]+)-(?P<service>[a-z0-9][a-z0-9-]*)"
    r"(?:@(?P<release>[A-Za-z0-9._-]+))?$"
)


#: What a release key may look like.
#:
#: **One path component, and it must not be able to act like a path.** A
#: release reaches the filesystem as a cache filename, and `pathlib` discards
#: everything to its left when joined with an absolute value, so an unchecked
#: release is an arbitrary-write primitive. Leading with an alphanumeric rules
#: out `.`, `..` and anything that reads as a flag; the class excludes the
#: separators outright.
#:
#: This constrains the release the **server** returns as well as the one a
#: caller types. The reference grammar above already excluded a slash from
#: what a caller can type, which is exactly why the gap was only ever on the
#: server's side of the exchange.
RELEASE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def is_release(value: str) -> bool:
    """Report whether a value is safe to use as a release key.

    Args:
        value: The release, from a caller or from the API.

    Returns:
        True when it is a single, inert path component.
    """
    return RELEASE_PATTERN.match(value) is not None


@dataclass(frozen=True)
class TmRef:
    """One ThreatModel, and optionally the release to read.

    Attributes:
        provider: The cloud provider segment, such as ``aws``.
        service: The service segment, such as ``s3``.
        release: The release key, or None for whichever is latest.
    """

    provider: str
    service: str
    release: str | None = None

    @property
    def tm_id(self) -> str:
        """The identifier as the catalogue spells it.

        Returns:
            ``provider-service``, without any release suffix.
        """
        return f"{self.provider}-{self.service}"

    def __str__(self) -> str:
        """Render the reference the way a caller types it.

        Returns:
            The id, with ``@release`` appended when one is pinned.
        """
        return f"{self.tm_id}@{self.release}" if self.release else self.tm_id


def is_remote_ref(value: str) -> bool:
    """Report whether a source string looks like a ThreatModel reference.

    Args:
        value: The source as the caller typed it.

    Returns:
        True when it matches the reference grammar.
    """
    return REF_PATTERN.match(value) is not None


def parse_ref(value: str) -> TmRef:
    """Parse a ThreatModel reference.

    Args:
        value: ``provider-service`` with an optional ``@release``.

    Returns:
        The parsed reference.

    Raises:
        ValueError: If the value is not a reference.

    Example:
        >>> parse_ref("aws-s3@1611187200")
        TmRef(provider='aws', service='s3', release='1611187200')
    """
    match = REF_PATTERN.match(value)
    if match is None:
        raise ValueError(
            f"{value!r} is not a ThreatModel reference; expected "
            "provider-service, optionally with @release"
        )
    release = match.group("release")
    if release is not None and not is_release(release):
        raise ValueError(f"{release!r} is not a usable release key.")
    return TmRef(
        provider=match.group("provider"),
        service=match.group("service"),
        release=release,
    )

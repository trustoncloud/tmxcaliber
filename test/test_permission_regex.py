"""Tests for the Azure ``ApiKey/...`` tokens in the permission regex.

TM QA rule E93 flags every threat ``access`` leaf that fails
``PERMISSION_REGEX[provider]``, so a key name missing from the alternation
raises a false finding on every Azure ThreatModel that uses it.
"""

import pytest

from tmxcaliber.lib.permission_json import PERMISSION_REGEX


@pytest.mark.parametrize(
    "perm",
    ["ApiKey/adminKey", "ApiKey/queryKey", "ApiKey/secretKey", "ApiKey/key"],
)
def test_a_known_azure_api_key_is_accepted(perm: str) -> None:
    # Arrange
    pattern = PERMISSION_REGEX["azure"]

    # Act
    match = pattern.search(perm)

    # Assert
    assert match is not None


@pytest.mark.parametrize("perm", ["ApiKey/keys", "ApiKey/otherKey", "ApiKey/"])
def test_an_unknown_azure_api_key_is_rejected(perm: str) -> None:
    # Arrange
    pattern = PERMISSION_REGEX["azure"]

    # Act
    match = pattern.search(perm)

    # Assert
    assert match is None

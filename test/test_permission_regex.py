"""Tests for Azure credential tokens in the permission regex.

TM QA rule E93 flags every threat ``access`` leaf that fails
``PERMISSION_REGEX[provider]``, so a credential form missing from the alternation
raises a false finding on every Azure ThreatModel that uses it.
"""

import pytest

from tmxcaliber.lib.permission_json import PERMISSION_REGEX


@pytest.mark.parametrize(
    "perm",
    [
        "ApiKey/adminKey",
        "ApiKey/queryKey",
        "ApiKey/secretKey",
        "ApiKey/key",
        "ApiKey/clientCertificate",
    ],
)
def test_a_known_azure_api_key_is_accepted(perm: str) -> None:
    # Arrange
    pattern = PERMISSION_REGEX["azure"]

    # Act
    match = pattern.search(perm)

    # Assert
    assert match is not None


@pytest.mark.parametrize(
    "perm",
    [
        "ApiKey/keys",
        "ApiKey/otherKey",
        "ApiKey/",
        "ApiKey:clientCertificate",
        "ApiKey/clientcertificate",
    ],
)
def test_an_unknown_azure_api_key_is_rejected(perm: str) -> None:
    # Arrange
    pattern = PERMISSION_REGEX["azure"]

    # Act
    match = pattern.search(perm)

    # Assert
    assert match is None


@pytest.mark.parametrize(
    "perm",
    [
        "AccessToken/token",
        "AccessToken/Token123",
        "AccessToken/eyJhbGci.eyJzdWI.signature",
        "AccessToken/.",
    ],
)
def test_azure_access_token_is_accepted(perm: str) -> None:
    assert PERMISSION_REGEX["azure"].fullmatch(perm) is not None


@pytest.mark.parametrize(
    "perm",
    [
        "AccessToken/",
        "AccessToken/token_value",
        "AccessToken/token-value",
        "AccessToken/token/value",
        "AccessToken:token",
        "AccessToken/token!",
    ],
)
def test_invalid_azure_access_token_is_rejected(perm: str) -> None:
    assert PERMISSION_REGEX["azure"].search(perm) is None

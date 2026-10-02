"""Credential resolution, the reference grammar, and leak avoidance."""

from __future__ import annotations

import pathlib

import pytest

from tmxcaliber.lib.remote.config import (
    DEFAULT_BASE_URL,
    Credentials,
    load_settings,
)
from tmxcaliber.lib.remote.errors import ConfigurationError
from tmxcaliber.lib.remote.ref import TmRef, is_remote_ref, parse_ref

KEY = "toc-tak1-" + "A" * 16 + "-" + "B" * 52
OTHER = "toc-tak1-" + "C" * 16 + "-" + "D" * 52


def test_the_environment_supplies_the_key() -> None:
    found = load_settings(env={"TOC_API_KEY": KEY})

    assert found.credentials.api_key == KEY
    assert found.base_url == DEFAULT_BASE_URL


def test_the_environment_beats_the_file(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "credentials"
    config.write_text(f"[default]\napi_key = {OTHER}\n", encoding="utf-8")

    found = load_settings(env={"TOC_API_KEY": KEY, "TOC_CONFIG_FILE": str(config)})

    assert found.credentials.api_key == KEY


def test_the_file_supplies_the_key_and_the_endpoint(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "credentials"
    config.write_text(
        f"[default]\napi_key = {KEY}\napi_url = https://api-staging.example\n",
        encoding="utf-8",
    )

    found = load_settings(env={"TOC_CONFIG_FILE": str(config)})

    assert found.credentials.api_key == KEY
    assert found.base_url == "https://api-staging.example"


def test_a_named_profile_is_selected(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "credentials"
    config.write_text(
        f"[default]\napi_key = {OTHER}\n\n[staging]\napi_key = {KEY}\n",
        encoding="utf-8",
    )

    found = load_settings(profile="staging", env={"TOC_CONFIG_FILE": str(config)})

    assert found.credentials.api_key == KEY


def test_no_key_anywhere_says_how_to_set_one() -> None:
    with pytest.raises(ConfigurationError) as caught:
        load_settings(env={"TOC_CONFIG_FILE": "/nonexistent/credentials"})

    message = str(caught.value)
    assert "TOC_API_KEY" in message
    assert "~/.trustoncloud/credentials" in message


def test_a_malformed_key_is_refused_before_any_call() -> None:
    # Otherwise a typo becomes a 401, which also spends one of the sixty
    # failed authentications a minute the API allows a source address.
    with pytest.raises(ConfigurationError) as caught:
        load_settings(env={"TOC_API_KEY": "nope"})

    assert "not a TrustOnCloud key" in str(caught.value)
    # The rejected value is described, never echoed: a key mistyped by one
    # character is still a secret.
    assert "nope" not in str(caught.value)


def test_the_credential_never_renders_itself() -> None:
    # repr reaches pytest assertion dumps and traceback frames.
    credential = Credentials(api_key=KEY, source="TOC_API_KEY")

    assert KEY not in repr(credential)
    assert "TOC_API_KEY" in repr(credential)


def test_the_settings_repr_does_not_leak_the_key() -> None:
    found = load_settings(env={"TOC_API_KEY": KEY})

    assert KEY not in repr(found)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("aws-s3", TmRef("aws", "s3")),
        ("gcp-bigquery", TmRef("gcp", "bigquery")),
        ("azure-storage", TmRef("azure", "storage")),
        ("aws-apigatewayv2", TmRef("aws", "apigatewayv2")),
        ("aws-s3@1611187200", TmRef("aws", "s3", "1611187200")),
    ],
)
def test_references_parse(value: str, expected: TmRef) -> None:
    assert parse_ref(value) == expected


def test_a_service_keeps_every_hyphen_after_the_first() -> None:
    # No published model needs this today, because service names are
    # collapsed, but nothing enforces that and a single split costs nothing.
    assert parse_ref("aws-api-gateway") == TmRef("aws", "api-gateway")


def test_a_reference_round_trips() -> None:
    assert str(parse_ref("aws-s3@1611187200")) == "aws-s3@1611187200"
    assert parse_ref("aws-s3").tm_id == "aws-s3"


@pytest.mark.parametrize(
    "value",
    [
        "threatmodel.json",
        "./aws-s3.json",
        "/tmp/aws-s3",
        "aws",
        "AWS-S3",
        "aws_s3",
        "",
        "aws-s3@",
    ],
)
def test_things_that_are_not_references(value: str) -> None:
    # Each would otherwise turn a filesystem typo into a network error.
    assert is_remote_ref(value) is False


def test_parsing_a_non_reference_raises() -> None:
    with pytest.raises(ValueError):
        parse_ref("threatmodel.json")

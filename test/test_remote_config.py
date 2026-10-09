"""Credential resolution, the reference grammar, and leak avoidance."""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

import pytest

from tmxcaliber.lib.remote.config import (
    DEFAULT_BASE_URL,
    Credentials,
    load_settings,
    masked,
    write_credentials,
)
from tmxcaliber.lib.remote.errors import ConfigurationError
from tmxcaliber.lib.remote.ref import TmRef, is_remote_ref, parse_ref

KEY = "toc-tak1-" + "A" * 16 + "-" + "B" * 52
OTHER = "toc-tak1-" + "C" * 16 + "-" + "D" * 52


def write_config(path: pathlib.Path, body: str) -> pathlib.Path:
    """Write a credentials file the loader will accept.

    Owner-only, because the loader refuses anything wider and `init` is
    what creates it in real use.

    Args:
        path: Where to write.
        body: The INI contents.

    Returns:
        The path written.
    """
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)
    return path


#: An endpoint other than the default, as `init` would have stored it.
STORED_URL = "https://api.example.com"


@dataclass(frozen=True)
class EndpointCase:
    """Where the key and the endpoint come from in one test.

    Attributes:
        environment_key: Whether TOC_API_KEY is set.
        environment_url: TOC_API_URL's value, or empty to leave it unset.
        stored_url: The api_url the credentials file holds, or empty for none.
    """

    environment_key: bool
    environment_url: str
    stored_url: str

    def environment(self, tmp_path: pathlib.Path) -> dict[str, str]:
        """Write the credentials file and build the environment for this case.

        The file always holds a key, and a different one from the
        environment's, so a test can tell which of the two was used.

        Args:
            tmp_path: Where to write the credentials file.

        Returns:
            The environment to resolve settings from.
        """
        body = f"[default]\napi_key = {OTHER}\n"
        if self.stored_url:
            body += f"api_url = {self.stored_url}\n"
        config = write_config(tmp_path / "credentials", body)
        env = {"TOC_CONFIG_FILE": str(config)}
        if self.environment_key:
            env["TOC_API_KEY"] = KEY
        if self.environment_url:
            env["TOC_API_URL"] = self.environment_url
        return env


#: A key from the environment going to an endpoint from the file, which is
#: the one combination a reader is told about.
HAZARD = EndpointCase(True, "", STORED_URL)

#: The hazard, and the same with a blank TOC_API_URL, which counts as unset.
NOTED_CASES = [
    pytest.param(HAZARD, id="TOC_API_URL unset"),
    pytest.param(EndpointCase(True, "   ", STORED_URL), id="TOC_API_URL blank"),
]

#: An endpoint the caller chose, or the default, so there is nothing to say.
QUIET_CASES = [
    pytest.param(
        EndpointCase(True, "https://other.example", STORED_URL), id="TOC_API_URL set"
    ),
    pytest.param(EndpointCase(False, "", STORED_URL), id="key from the file"),
    pytest.param(EndpointCase(True, "", ""), id="no endpoint stored"),
    pytest.param(EndpointCase(True, "", DEFAULT_BASE_URL), id="stored default"),
    pytest.param(
        EndpointCase(True, "", DEFAULT_BASE_URL + "/"), id="stored default with slash"
    ),
]


def test_the_environment_supplies_the_key() -> None:
    found = load_settings(env={"TOC_API_KEY": KEY})

    assert found.credentials.api_key == KEY
    assert found.base_url == DEFAULT_BASE_URL


def test_the_environment_beats_the_file(tmp_path: pathlib.Path) -> None:
    config = write_config(tmp_path / "credentials", f"[default]\napi_key = {OTHER}\n")

    found = load_settings(env={"TOC_API_KEY": KEY, "TOC_CONFIG_FILE": str(config)})

    assert found.credentials.api_key == KEY


def test_the_file_supplies_the_key_and_the_endpoint(tmp_path: pathlib.Path) -> None:
    config = write_config(
        tmp_path / "credentials",
        f"[default]\napi_key = {KEY}\napi_url = https://api-staging.example\n",
    )

    found = load_settings(env={"TOC_CONFIG_FILE": str(config)})

    assert found.credentials.api_key == KEY
    assert found.base_url == "https://api-staging.example"


def test_there_are_no_profiles(tmp_path: pathlib.Path) -> None:
    """Only `[default]` is read, whatever else the file holds.

    One key, one endpoint, and `TOC_API_KEY` for the "a different one right
    now" case. A second section is a second way to say the same thing, and
    `init` could not write it anyway.
    """
    config = write_config(
        tmp_path / "credentials",
        f"[default]\napi_key = {KEY}\n\n[staging]\napi_key = {OTHER}\n",
    )

    found = load_settings(env={"TOC_CONFIG_FILE": str(config)})

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


@pytest.mark.parametrize(
    "url",
    ["http://api.trustoncloud.com", "http://evil.example", "ftp://api.example"],
)
def test_a_cleartext_endpoint_is_refused(url: str) -> None:
    """The key travels in a request header.

    A mistyped or untrusted `TOC_API_URL` would otherwise hand a live
    tenant credential to anyone able to watch the connection.
    """
    with pytest.raises(ConfigurationError) as caught:
        load_settings(env={"TOC_API_KEY": KEY, "TOC_API_URL": url})

    assert "https" in str(caught.value)


@pytest.mark.parametrize(
    "url", ["http://localhost:8081", "http://127.0.0.1:8081", "https://api.example"]
)
def test_loopback_and_https_endpoints_are_accepted(url: str) -> None:
    # Local development against a container on this machine is the one case
    # where plain HTTP never leaves the host.
    assert load_settings(env={"TOC_API_KEY": KEY, "TOC_API_URL": url}).base_url == url


def test_a_malformed_credentials_file_never_echoes_the_key(
    tmp_path: pathlib.Path,
) -> None:
    """ConfigParser puts the offending line into its exception.

    So a key written without its separator would be printed to a terminal
    or a CI log by the very error complaining about it.
    """
    config = write_config(tmp_path / "credentials", f"[default]\napi_key {KEY}\n")

    with pytest.raises(ConfigurationError) as caught:
        load_settings(env={"TOC_CONFIG_FILE": str(config)})

    message = str(caught.value)
    assert KEY not in message
    assert "toc-tak1" not in message
    assert "could not be parsed" in message


def test_a_credentials_file_other_users_can_read_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """The CLI writes this file at 0600, so a wider mode is hand-made.

    Under a default umask a hand-created file is 0644, which puts a tenant
    credential within reach of every other account on the machine.
    """
    config = tmp_path / "credentials"
    config.write_text(f"[default]\napi_key = {KEY}\n", encoding="utf-8")
    config.chmod(0o644)

    with pytest.raises(ConfigurationError) as caught:
        load_settings(env={"TOC_CONFIG_FILE": str(config)})

    message = str(caught.value)
    assert "readable by other users" in message
    # The cure, named, because a refusal with no next step is a dead end.
    assert "tmxcaliber init" in message
    assert KEY not in message


def test_the_written_file_is_owner_only(tmp_path: pathlib.Path) -> None:
    written = write_credentials(KEY, env={"TOC_CONFIG_FILE": str(tmp_path / "c")})

    assert written.stat().st_mode & 0o777 == 0o600
    assert (
        load_settings(env={"TOC_CONFIG_FILE": str(written)}).credentials.api_key == KEY
    )


def test_the_written_directory_is_owner_only(tmp_path: pathlib.Path) -> None:
    nested = tmp_path / "fresh" / "credentials"

    write_credentials(KEY, env={"TOC_CONFIG_FILE": str(nested)})

    assert nested.parent.stat().st_mode & 0o777 == 0o700


def test_a_written_endpoint_is_read_back(tmp_path: pathlib.Path) -> None:
    written = write_credentials(
        KEY,
        api_url="https://api-staging.example",
        env={"TOC_CONFIG_FILE": str(tmp_path / "c")},
    )

    assert load_settings(env={"TOC_CONFIG_FILE": str(written)}).base_url == (
        "https://api-staging.example"
    )


def test_writing_a_malformed_key_is_refused(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ConfigurationError):
        write_credentials("nope", env={"TOC_CONFIG_FILE": str(tmp_path / "c")})


def test_masking_keeps_the_id_and_hides_the_secret() -> None:
    # The id is public and is what support asks for; the secret never is.
    shown = masked(KEY)

    assert shown.startswith("toc-tak1-" + "A" * 16)
    assert "B" * 52 not in shown


def test_a_percent_in_the_file_never_reaches_an_error_message(
    tmp_path: pathlib.Path,
) -> None:
    """Interpolation is off, so a `%` cannot quote the key back at you.

    With it on, a value containing `%` raises InterpolationSyntaxError
    whose message includes the rest of that value. The earlier fix covered
    `parser.read`; this is the same disclosure through `parser.get`.
    """
    mangled = KEY[:20] + "%" + KEY[21:]
    config = write_config(tmp_path / "credentials", f"[default]\napi_key = {mangled}\n")

    with pytest.raises(ConfigurationError) as caught:
        load_settings(env={"TOC_CONFIG_FILE": str(config)})

    message = str(caught.value)
    # Refused for its shape, not by leaking it.
    assert "not a TrustOnCloud key" in message
    assert mangled not in message
    assert mangled[10:30] not in message


def test_a_stored_endpoint_survives_an_environment_key(
    tmp_path: pathlib.Path,
) -> None:
    """Setting TOC_API_KEY must not move which API is called.

    The file used to be read only when the key was absent, so an
    environment key silently returned a configured custom endpoint to the
    default, and `init` could verify one API while commands called
    another.
    """
    config = write_config(
        tmp_path / "credentials",
        f"[default]\napi_key = {OTHER}\napi_url = https://api.example.com\n",
    )

    found = load_settings(env={"TOC_API_KEY": KEY, "TOC_CONFIG_FILE": str(config)})

    assert found.credentials.api_key == KEY
    assert found.base_url == "https://api.example.com"


def test_an_environment_endpoint_still_wins_over_the_stored_one(
    tmp_path: pathlib.Path,
) -> None:
    config = write_config(
        tmp_path / "credentials",
        f"[default]\napi_key = {KEY}\napi_url = https://api.example.com\n",
    )

    found = load_settings(
        env={"TOC_API_URL": "https://other.example", "TOC_CONFIG_FILE": str(config)}
    )

    assert found.base_url == "https://other.example"


@pytest.mark.parametrize("case", NOTED_CASES)
def test_an_environment_key_going_to_a_stored_endpoint_is_flagged(
    tmp_path: pathlib.Path, case: EndpointCase
) -> None:
    """The hazard the CLI warns about, recorded rather than printed.

    A key exported for another API goes to the endpoint `init` stored,
    because the endpoint is resolved independently of the key. The
    precedence stays; the settings say where the endpoint came from.
    """
    env = case.environment(tmp_path)

    found = load_settings(env=env)

    assert found.credentials.api_key == KEY
    assert found.base_url == STORED_URL
    assert found.endpoint_source == env["TOC_CONFIG_FILE"]
    assert found.sends_key_to_stored_endpoint is True


@pytest.mark.parametrize("case", QUIET_CASES)
def test_an_endpoint_the_caller_chose_or_expects_is_not_flagged(
    tmp_path: pathlib.Path, case: EndpointCase
) -> None:
    found = load_settings(env=case.environment(tmp_path))

    assert found.sends_key_to_stored_endpoint is False


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        (EndpointCase(True, "https://other.example", STORED_URL), "TOC_API_URL"),
        (EndpointCase(True, "", STORED_URL), "file"),
        (EndpointCase(True, "", ""), ""),
    ],
)
def test_the_endpoint_records_where_it_came_from(
    tmp_path: pathlib.Path, case: EndpointCase, expected: str
) -> None:
    env = case.environment(tmp_path)

    found = load_settings(env=env)

    wanted = env["TOC_CONFIG_FILE"] if expected == "file" else expected
    assert found.endpoint_source == wanted

"""Source resolution and the API commands, driven through the real CLI."""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.parse
from argparse import Namespace
from collections.abc import Iterator, Mapping
from typing import Any, NoReturn

import pytest
from colorama import Fore

from tmxcaliber import cli as cli_module
from tmxcaliber import remote_cli
from tmxcaliber.lib.remote.client import TocClient
from tmxcaliber.lib.remote.config import Settings
from tmxcaliber.lib.remote.contract import route_for
from tmxcaliber.lib.remote.errors import (
    AuthenticationError,
    NotFound,
    ServiceUnavailable,
)
from tmxcaliber.lib.remote.resolve import resolve_source
from tmxcaliber.remote_cli import (
    connect,
    resolve_command_source,
    run_api_command,
    run_ccr_fetch,
)

from .test_remote_api import page
from .test_remote_assemble import DETAIL, DFD, PARTS, _at_release
from .test_remote_ccr import PackClient, readable_packs, two_packs
from .test_remote_client import FakeOpener, FakeResponse, StrictOpener, http_error
from .test_remote_client import settings as client_settings
from .test_remote_config import (
    HAZARD,
    NOTED_CASES,
    QUIET_CASES,
    STORED_URL,
    EndpointCase,
)
from .test_remote_suggest import THREATMODELS as CATALOGUE


class StubClient:
    """Answers the five assembly calls and records them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        # What the stub's collections say beyond their rows.
        self.envelope_fields: dict[str, Any] = {}
        # The fields the last walk was told every page must carry.
        self.required: dict[str, tuple[type, ...]] = {}

    key: str = "KEYONE"

    @property
    def base_url(self) -> str:
        """The endpoint, for cache keying.

        Returns:
            A stable fake.
        """
        return "https://api.example.test"

    @property
    def key_id(self) -> str:
        """Which credential this stub speaks as.

        Returns:
            The fake key id.
        """
        return self.key

    def get(self, path: str, params: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Answer a single-resource call.

        Args:
            path: The path.
            params: The query.

        Returns:
            The fixture for that path.
        """
        self.calls.append((path, dict(params or {})))
        if path.endswith("/dfd"):
            return dict(DFD)
        # A real detail route answers for the release it was asked for, and
        # the assembler refuses an answer that names a different one.
        asked = dict(params or {}).get("release")
        if path == "/v1/me":
            return {"tenantId": "t-1", "permissions": ["api.threatmodels.read"]}
        return _at_release(DETAIL, asked)

    def paginate(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        page_size: int = 0,
        envelope: dict[str, Any] | None = None,
        required: Mapping[str, tuple[type, ...]] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Answer a collection call.

        Args:
            path: The path.
            params: The query.
            page_size: Ignored.
            envelope: Filled with ``envelope_fields``.
            required: Recorded, for the caller to assert on.

        Yields:
            Fixture rows.
        """
        self.calls.append((path, dict(params or {})))
        self.required = dict(required or {})
        if envelope is not None:
            envelope.update(self.envelope_fields)
        section = path.rsplit("/", 1)[-1]
        if section in PARTS:
            yield from PARTS[section]
        else:
            yield {"tmId": "aws-s3", "title": "Amazon S3"}


def test_a_path_that_exists_is_returned_unchanged(tmp_path: pathlib.Path) -> None:
    # Disk wins. This is what keeps every existing invocation meaning what
    # it meant.
    model = tmp_path / "aws-s3"
    model.write_text("{}", encoding="utf-8")

    assert resolve_source(str(model)) == str(model)


def test_something_that_is_neither_is_handed_back_untouched() -> None:
    # So the caller's own validator produces the message it always produced,
    # rather than a confusing network error for a mistyped filename.
    assert resolve_source("threatmodel.json") == "threatmodel.json"


def test_a_reference_is_fetched_and_cached(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = {"TMXCALIBER_CACHE_DIR": str(tmp_path / "cache")}
    client = StubClient()

    path = resolve_source("aws-s3", client=client, env=env)  # type: ignore[arg-type]

    document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    assert sorted(document) == [
        "actions",
        "control_objectives",
        "controls",
        "dfd",
        "feature_classes",
        "metadata",
        "scorecard",
        "threats",
    ]
    assert len(client.calls) == 5


def test_a_second_resolve_is_served_from_the_cache(tmp_path: pathlib.Path) -> None:
    env = {"TMXCALIBER_CACHE_DIR": str(tmp_path / "cache")}
    first = StubClient()
    resolve_source("aws-s3", client=first, env=env)  # type: ignore[arg-type]

    second = StubClient()
    resolve_source("aws-s3", client=second, env=env)  # type: ignore[arg-type]

    # Nothing at all the second time, inside the cache's lifetime. A filter
    # loop over one reference must not cost five calls each pass.
    assert len(first.calls) == 5
    assert second.calls == []


def test_an_api_command_runs_and_returns_json() -> None:
    route = route_for(("threatmodels", "threats"))
    assert route is not None
    params = Namespace(
        api_route=route, tm_id="aws-s3", feature_class="", release="", limit=0
    )

    result, kind = run_api_command(params, client=StubClient())  # type: ignore[arg-type]

    assert kind == "json"
    assert isinstance(result, list)
    assert result[0]["threatId"] == "S3.T1"


def test_what_a_collection_says_beyond_its_rows_reaches_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Unresolved ThreatModels mean the rows are incomplete. Printing them on
    # stderr tells a person without changing what a script reads on stdout.
    route = route_for(("compliance", "mappings", "list"))
    assert route is not None
    client = StubClient()
    client.envelope_fields = {"unresolvedTmIds": ["aws-s3"], "empty": []}
    params = Namespace(api_route=route, framework="nist-800-53-r5", service="", limit=0)

    result, _ = run_api_command(params, client=client)  # type: ignore[arg-type]

    assert isinstance(result, list)
    err = capsys.readouterr().err
    assert 'unresolvedTmIds: ["aws-s3"]' in err
    assert "empty" not in err


def test_unresolved_threatmodels_mark_the_answer_incomplete() -> None:
    route = route_for(("compliance", "mappings", "list"))
    assert route is not None
    client = StubClient()
    client.envelope_fields = {"unresolvedTmIds": ["aws-s3"]}
    params = Namespace(api_route=route, framework="nist-800-53-r5", service="", limit=0)
    incomplete: list[str] = []

    run_api_command(params, client=client, incomplete=incomplete)  # type: ignore[arg-type]

    assert incomplete == ['unresolvedTmIds: ["aws-s3"]']
    # The walk is held to the fields the contract makes required.
    assert client.required == {"unresolvedTmIds": (list,)}


def test_an_empty_unresolved_list_is_a_complete_answer() -> None:
    route = route_for(("compliance", "mappings", "list"))
    assert route is not None
    client = StubClient()
    client.envelope_fields = {"unresolvedTmIds": []}
    params = Namespace(api_route=route, framework="nist-800-53-r5", service="", limit=0)
    incomplete: list[str] = []

    run_api_command(params, client=client, incomplete=incomplete)  # type: ignore[arg-type]

    assert incomplete == []


def _run_cli(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], reported: list[str]
) -> int:
    """Run the CLI over a stubbed API command that reports `reported`.

    Args:
        monkeypatch: Replaces argv and the command runner.
        argv: The words after the program name.
        reported: The incompleteness lines the stub reports.

    Returns:
        The exit status.
    """

    def fake_run(_params: Namespace, *, incomplete: list[str]) -> tuple[Any, str]:
        incomplete.extend(reported)
        return [{"frameworkId": "nist-800-53-r5"}], "json"

    monkeypatch.setattr(cli_module, "run_api_command", fake_run)
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", *argv])
    with pytest.raises(SystemExit) as caught:
        cli_module._run()
        raise SystemExit(0)
    return int(caught.value.code or 0)


def test_an_incomplete_answer_is_written_and_exits_three(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: pathlib.Path,
) -> None:
    # Written first, so what the API did answer is kept; the status is what a
    # script sees.
    out = tmp_path / "mappings.json"
    argv = ["compliance", "mappings", "list", "--framework", "x", "--output", str(out)]

    status = _run_cli(monkeypatch, argv, ['unresolvedTmIds: ["aws-s3"]'])

    assert status == 3
    assert json.loads(out.read_text())[0]["frameworkId"] == "nist-800-53-r5"
    assert "--allow-incomplete" in capsys.readouterr().err


def test_allow_incomplete_accepts_a_partial_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    out = tmp_path / "mappings.json"
    argv = [
        "compliance",
        "mappings",
        "list",
        "--framework",
        "x",
        "--output",
        str(out),
        "--allow-incomplete",
    ]

    status = _run_cli(monkeypatch, argv, ['unresolvedTmIds: ["aws-s3"]'])

    assert status == 0


def test_only_a_route_that_can_be_incomplete_offers_the_option(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mappings = _help_of(monkeypatch, capsys, ["compliance", "mappings", "list"])
    threatmodels = _help_of(monkeypatch, capsys, ["threatmodels", "list"])

    assert "--allow-incomplete" in mappings
    assert "--allow-incomplete" not in threatmodels


def test_an_at_release_suffix_becomes_the_query_parameter() -> None:
    # A caller can pin either way, and only one of them reaches the wire.
    route = route_for(("threatmodels", "get"))
    assert route is not None
    params = Namespace(api_route=route, tm_id="aws-s3@1600000000", release="")
    client = StubClient()

    run_api_command(params, client=client)  # type: ignore[arg-type]

    assert client.calls[0] == (
        "/v1/threatmodels/aws/s3",
        {"release": "1600000000"},
    )


def test_an_explicit_release_flag_wins_over_the_suffix() -> None:
    route = route_for(("threatmodels", "get"))
    assert route is not None
    params = Namespace(api_route=route, tm_id="aws-s3@1600000000", release="1700000000")
    client = StubClient()

    run_api_command(params, client=client)  # type: ignore[arg-type]

    assert client.calls[0][1] == {"release": "1700000000"}


def test_no_credential_exits_one_and_opens_no_socket(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The conftest guard means a socket would fail the test outright, so
    # this also proves the refusal happens before any connection.
    monkeypatch.delenv("TOC_API_KEY", raising=False)
    monkeypatch.setenv("TOC_CONFIG_FILE", "/nonexistent/credentials")
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "me"])

    with pytest.raises(SystemExit) as caught:
        cli_module.main()

    assert caught.value.code == 1
    assert "TOC_API_KEY" in capsys.readouterr().out


def test_the_api_commands_are_reachable_from_the_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "threatmodels", "get", "aws-s3"])

    params = cli_module.get_params()

    assert params.api_route is not None
    assert params.api_route.path == "/v1/threatmodels/{provider}/{service}"
    assert params.tm_id == "aws-s3"


def _help_of(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> str:
    """Render a command's help through the real parser.

    Args:
        monkeypatch: Sets argv.
        capsys: Captures the help.
        argv: The words after the program name, without -h.

    Returns:
        The printed help.
    """
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", *argv, "-h"])
    with pytest.raises(SystemExit):
        cli_module.get_params()
    return capsys.readouterr().out


def test_a_required_filter_is_listed_as_required_and_names_its_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    text = _help_of(monkeypatch, capsys, ["compliance", "mappings", "list"])

    required = text.split("required arguments:", 1)[1]
    assert "--framework" in required
    assert "tmxcaliber compliance frameworks list" in required
    assert "filter by framework" not in text


def test_the_group_help_says_what_its_command_needs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    text = _help_of(monkeypatch, capsys, ["compliance", "mappings"])

    assert "Requires --framework." in " ".join(text.split())


def test_an_optional_filter_keeps_its_wording(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    text = _help_of(monkeypatch, capsys, ["threatmodels", "list"])

    assert "filter by provider." in text
    assert "required arguments:" not in text


def test_the_archive_options_say_what_they_choose(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Neither option narrows a collection, so "filter by kind." and "filter by
    # release." told the reader nothing about what to pass.
    text = " ".join(_help_of(monkeypatch, capsys, ["ccr", "packs", "archive"]).split())

    assert (
        "which archive to download: source (the default, the rule tree) or deploy "
        "(the Terraform package)." in text
    )
    assert (
        "the release to pin the download to, as `tmxcaliber ccr packs get` reports "
        "it; the API refuses a release it no longer publishes." in text
    )
    assert "filter by kind" not in text
    assert "filter by release" not in text


def test_a_release_filter_elsewhere_keeps_its_wording(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    text = _help_of(monkeypatch, capsys, ["threatmodels", "get"])

    assert "filter by release." in text


def test_a_second_credential_does_not_read_the_first_one_s_cache(
    tmp_path: pathlib.Path,
) -> None:
    """Entitlement is decided per key, so the cache cannot be shared.

    Without the credential in the cache key, a second key reads a document
    the first one fetched with no request, and therefore no entitlement
    check. Revoking the first key would not stop it.
    """
    env = {"TMXCALIBER_CACHE_DIR": str(tmp_path / "cache")}
    first = StubClient()
    first.key = "KEYONE"
    resolve_source("aws-s3", client=first, env=env)  # type: ignore[arg-type]

    second = StubClient()
    second.key = "KEYTWO"
    resolve_source("aws-s3", client=second, env=env)  # type: ignore[arg-type]

    assert len(second.calls) == 5, "the second credential reused the first's cache"


def test_generate_accepts_a_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    """The documented `tmxcaliber generate aws-s3` must parse.

    `validate` rejects a source without a .json or _DFD.xml suffix, and it
    runs before the document is fetched, so a reference has to be exempt or
    the command exits 2.
    """
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "generate", "aws-s3"])

    params = cli_module.get_params()

    assert params.source == "aws-s3"


def test_an_unpinned_fetch_satisfies_a_later_pinned_request(
    tmp_path: pathlib.Path,
) -> None:
    """The pinned copy is filed under the API's release.

    Keyed from `metadata.version` instead, it landed under the schema date,
    so every pinned request missed and repeated the whole five-call
    assembly against an hourly budget.
    """
    env = {"TMXCALIBER_CACHE_DIR": str(tmp_path / "cache")}
    first = StubClient()
    resolve_source("aws-s3", client=first, env=env)  # type: ignore[arg-type]
    assert len(first.calls) == 5

    pinned = StubClient()
    path = resolve_source(  # type: ignore[arg-type]
        "aws-s3@1611187200", client=pinned, env=env
    )

    assert pinned.calls == [], "the pinned request repeated the assembly"
    assert path.endswith("1611187200.json")


#: How the stored-endpoint note starts, wherever a test only needs to find it.
NOTE = "Note: the key in TOC_API_KEY will be sent to"


@pytest.fixture(autouse=True)
def fresh_notes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forget the stored-endpoint notes earlier tests wrote.

    The CLI says it once per process, which is once per invocation in real
    use but once per whole session under pytest.

    Args:
        monkeypatch: Replaces the record for this test only.
    """
    monkeypatch.setattr(remote_cli, "_noted", set())


class SettingsStub(StubClient):
    """A StubClient built the way `connect` builds a real client."""

    def __init__(self, settings: Settings) -> None:
        """Keep the settings `connect` resolved.

        Args:
            settings: The resolved settings.
        """
        super().__init__()
        self.settings = settings


class RefusingClient(SettingsStub):
    """Refuses every call, as an API that does not know the key would."""

    def get(self, path: str, params: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Refuse the call.

        Args:
            path: The path.
            params: The query.

        Raises:
            AuthenticationError: Always.
        """
        raise AuthenticationError("The API key was not accepted.", status=401)


def _use_environment(
    monkeypatch: pytest.MonkeyPatch, env: Mapping[str, str], tmp_path: pathlib.Path
) -> None:
    """Make `env` the whole of the credential environment, for the real CLI.

    Args:
        monkeypatch: Sets and clears the variables.
        env: The variables to set.
        tmp_path: Holds the document cache and is the working directory, so
            a reference cannot collide with a file of the same name.
    """
    for name in ("TOC_API_KEY", "TOC_API_URL", "TOC_CONFIG_FILE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("TMXCALIBER_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.chdir(tmp_path)


@pytest.mark.parametrize("case", NOTED_CASES)
def test_a_stored_endpoint_under_an_environment_key_is_noted_on_stderr(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: EndpointCase,
) -> None:
    env = case.environment(tmp_path)
    monkeypatch.setattr(remote_cli, "TocClient", SettingsStub)

    connect(env=env)

    captured = capsys.readouterr()
    assert (
        f"Note: the key in TOC_API_KEY will be sent to {STORED_URL}, the "
        f"endpoint stored in {env['TOC_CONFIG_FILE']}. Set TOC_API_URL to "
        "choose a different endpoint."
    ) in captured.err
    assert captured.out == ""


@pytest.mark.parametrize("case", QUIET_CASES)
def test_nothing_is_said_about_an_endpoint_the_caller_chose_or_expects(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: EndpointCase,
) -> None:
    monkeypatch.setattr(remote_cli, "TocClient", SettingsStub)

    connect(env=case.environment(tmp_path))

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_an_api_command_notes_on_stderr_and_leaves_stdout_to_the_json(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_environment(monkeypatch, HAZARD.environment(tmp_path), tmp_path)
    monkeypatch.setattr(remote_cli, "TocClient", SettingsStub)
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "me"])

    cli_module.main()

    captured = capsys.readouterr()
    assert json.loads(captured.out)["tenantId"] == "t-1"
    assert NOTE in captured.err


def test_the_note_is_written_even_when_the_request_then_fails(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The caller most needs to know which API refused the key.
    _use_environment(monkeypatch, HAZARD.environment(tmp_path), tmp_path)
    monkeypatch.setattr(remote_cli, "TocClient", RefusingClient)
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "me"])

    with pytest.raises(SystemExit) as caught:
        cli_module.main()

    captured = capsys.readouterr()
    assert caught.value.code == 1
    assert NOTE in captured.err
    assert NOTE not in captured.out


def test_a_reference_given_as_a_document_source_is_noted_too(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_environment(monkeypatch, HAZARD.environment(tmp_path), tmp_path)
    monkeypatch.setattr(remote_cli, "TocClient", SettingsStub)
    argv = ["tmxcaliber", "list", "feature-classes", "aws-s3", "--format", "json"]
    monkeypatch.setattr(sys, "argv", argv)

    cli_module.main()

    captured = capsys.readouterr()
    assert isinstance(json.loads(captured.out), list)
    assert NOTE in captured.err


def test_the_note_is_written_once_per_run(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # `create-change-log` resolves two references in one run.
    _use_environment(monkeypatch, HAZARD.environment(tmp_path), tmp_path)
    monkeypatch.setattr(remote_cli, "TocClient", SettingsStub)

    resolve_command_source("aws-s3")
    resolve_command_source("aws-s3")

    assert capsys.readouterr().err.count(NOTE) == 1


def test_a_local_file_never_resolves_a_credential(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Laziness is what lets a caller work on a file with no key configured.
    _use_environment(monkeypatch, HAZARD.environment(tmp_path), tmp_path)
    model = tmp_path / "aws-s3"
    model.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(remote_cli, "connect", _never_called)

    assert resolve_command_source(str(model)) == str(model)
    assert capsys.readouterr().err == ""


def _never_called() -> NoReturn:
    """Stand in for `connect` where a source must not reach the API.

    Raises:
        AssertionError: Always.
    """
    raise AssertionError("a local source reached for a credential")


class BytesStubClient(StubClient):
    """Answers a binary route with a fixed archive."""

    archive = b"PK\x03\x04\xff"

    def get_bytes(self, path: str, params: Mapping[str, str] | None = None) -> bytes:
        """Answer a binary call.

        Args:
            path: The path.
            params: The query.

        Returns:
            The archive.
        """
        self.calls.append((path, dict(params or {})))
        return self.archive


def test_the_archive_command_needs_a_file_to_write_to(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["tmxcaliber", "ccr", "packs", "archive", "aws-s3"]
    )

    with pytest.raises(SystemExit):
        cli_module.get_params()

    assert "--output" in capsys.readouterr().err


def test_the_archive_command_writes_the_bytes(tmp_path: pathlib.Path) -> None:
    route = route_for(("ccr", "packs", "archive"))
    assert route is not None
    params = Namespace(api_route=route, release_key="aws-s3", kind="deploy", release="")
    client = BytesStubClient()

    result, kind = run_api_command(params, client=client)  # type: ignore[arg-type]
    cli_module.output_result(str(tmp_path / "pack.zip"), result, kind)

    assert kind == "bytes"
    assert (tmp_path / "pack.zip").read_bytes() == BytesStubClient.archive
    assert client.calls == [
        ("/v1/ccr/packs/aws-s3/archive", {"kind": "deploy", "release": ""})
    ]


def _fetch_params(monkeypatch: pytest.MonkeyPatch, *words: str) -> Namespace:
    """Parse a `ccr fetch` command through the real parser.

    Args:
        monkeypatch: Sets argv.
        *words: The words after `ccr fetch`.

    Returns:
        The parsed arguments.
    """
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "ccr", "fetch", *words])
    return cli_module.get_params()


def test_fetch_parses_every_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    params = _fetch_params(
        monkeypatch,
        "aws-s3",
        "--control",
        "S3.C20",
        "--mode",
        "allowlist",
        "--matcher",
        "terraform",
        "--file",
        "*.rego",
        "--out",
        "rules",
    )

    assert params.ccr_fetch is True
    assert params.release_keys == ["aws-s3"]
    assert (params.control, params.mode, params.matcher, params.file) == (
        ["S3.C20"],
        ["allowlist"],
        ["terraform"],
        ["*.rego"],
    )
    assert params.out == "rules"


@pytest.mark.parametrize(
    ("option", "value"),
    [("--mode", "sometimes"), ("--mode", "Universal"), ("--matcher", "clouds")],
)
def test_fetch_refuses_an_unknown_mode_or_matcher_as_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
) -> None:
    # argparse refuses it before `RuleFilter` can, so the command line keeps
    # its usage line and exit status 2 instead of a ValueError traceback.
    with pytest.raises(SystemExit) as exited:
        _fetch_params(monkeypatch, option, value)

    assert exited.value.code == 2
    assert f"invalid choice: '{value}'" in capsys.readouterr().err


def test_fetch_prints_rows_as_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "--control", "S3.C20")

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    assert status == 0
    assert [row["ruleId"] for row in json.loads(capsys.readouterr().out)] == ["S3.C20"]


def test_fetch_with_no_match_prints_an_empty_list_and_a_note(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "--control", "Nothing.C1")

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert status == 0
    assert json.loads(captured.out) == []
    assert "No rule matched" in captured.err


# The tests above that parse a command only read the namespace, so each filter
# below is run through `fetch` and judged by what comes out. A flag wired to the
# wrong argument, or dropped, then changes the rows instead of passing unseen.


@pytest.mark.parametrize(
    ("words", "release_keys"),
    [
        (("--provider", "gcp"), {"gcp-bigquery"}),
        (("--service", "s3"), {"aws-s3"}),
    ],
    ids=["provider", "service"],
)
def test_fetch_narrows_the_packs_by_provider_or_service(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    words: tuple[str, ...],
    release_keys: set[str],
) -> None:
    params = _fetch_params(monkeypatch, *words)

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    rows = json.loads(capsys.readouterr().out)
    assert status == 0
    assert {row["releaseKey"] for row in rows} == release_keys


def test_fetch_selects_only_rules_that_ship_the_mode(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "--mode", "denylist")

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert status == 0
    assert json.loads(captured.out) == []
    assert "No rule matched" in captured.err


def test_fetch_selects_by_mode_and_matcher_together(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "--mode", "allowlist", "--matcher", "cloud")

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    rows = json.loads(capsys.readouterr().out)
    assert status == 0
    assert [row["ruleId"] for row in rows] == ["S3.C20", "S3.C21", "Bigquery.C102"]


def test_fetch_matcher_leaves_out_the_files_of_the_other_matcher(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(
        monkeypatch, "aws-s3", "--matcher", "terraform", "--control", "S3.C20"
    )

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    rows = json.loads(capsys.readouterr().out)
    assert status == 0
    assert [row["files"] for row in rows] == [["metadata.json"]]


def test_fetch_writes_files_and_prints_their_paths(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    params = _fetch_params(
        monkeypatch, "aws-s3", "--file", "*.rego", "--out", str(tmp_path)
    )

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    written = tmp_path / "aws-s3" / "S3.C20" / "allowlist" / "cloud" / "check.rego"
    assert status == 0
    assert capsys.readouterr().out.split() == [str(written)]
    assert written.exists()


def test_fetch_refuses_packs_and_a_provider_together(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "aws-s3", "--provider", "aws")

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    assert status == 2
    assert "not both" in capsys.readouterr().err


def test_a_failed_pack_exits_non_zero_and_names_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "aws-nothing")

    status = run_ccr_fetch(params, client=PackClient(two_packs()))  # type: ignore[arg-type]

    err = capsys.readouterr().err
    assert status == 1
    assert "aws-nothing: manifest failed: " in err
    assert "not_found" in err
    # Nothing matched because the pack failed, which the line above says, so
    # a note about the filters would point the reader the wrong way.
    assert "No rule matched" not in err


def test_an_unknown_pack_ends_with_what_it_probably_meant(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    params = _fetch_params(monkeypatch, "ec3")

    status = run_ccr_fetch(params, client=PackClient(readable_packs("aws-ec2")))  # type: ignore[arg-type]

    [line] = capsys.readouterr().err.splitlines()
    assert status == 1
    assert line.startswith(Fore.RED + "ec3: manifest failed: ")
    assert line.endswith("Did you mean aws-ec2?" + Fore.RESET)


@pytest.mark.parametrize(
    ("words", "expected"),
    [
        (
            ("--service", "gemini-agent-platform"),
            "No pack this key can read matches --service 'gemini-agent-platform'. "
            "Did you mean gcp-vertex?",
        ),
        (
            ("--provider", "gpc"),
            "No pack this key can read matches --provider 'gpc'. Did you mean gcp?",
        ),
    ],
    ids=["service", "provider"],
)
def test_a_narrowing_no_pack_has_exits_one_and_says_what_was_close(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    words: tuple[str, ...],
    expected: str,
) -> None:
    params = _fetch_params(monkeypatch, *words)

    status = run_ccr_fetch(params, client=PackClient(readable_packs("gcp-vertex")))  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert status == 1
    # Nothing was selected, so there are no rows to print, and the one line
    # on stderr puts the blame on the narrowing.
    assert captured.out == ""
    assert captured.err == Fore.RED + expected + Fore.RESET + "\n"


def test_the_service_a_refusal_suggests_is_accepted_when_typed_back(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = PackClient(readable_packs("gcp-vertex"))
    refused = run_ccr_fetch(
        _fetch_params(monkeypatch, "--service", "Gemini Agent Platform"),
        client=client,  # type: ignore[arg-type]
    )
    assert refused == 1
    assert "Did you mean gcp-vertex?" in capsys.readouterr().err

    status = run_ccr_fetch(
        _fetch_params(monkeypatch, "--service", "gcp-vertex"),
        client=client,  # type: ignore[arg-type]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert captured.err == ""
    assert {row["releaseKey"] for row in json.loads(captured.out)} == {"gcp-vertex"}


def test_the_service_a_refusal_suggests_beside_a_provider_names_that_provider(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = PackClient(two_packs())
    first = run_ccr_fetch(
        _fetch_params(monkeypatch, "--provider", "aws", "--service", "bigquery"),
        client=client,  # type: ignore[arg-type]
    )
    assert first == 1
    assert capsys.readouterr().err == (
        Fore.RED + "No pack this key can read matches --provider 'aws' and --service "
        "'bigquery'. Did you mean gcp-bigquery? gcp-bigquery belongs to gcp, which "
        "--provider 'aws' leaves out." + Fore.RESET + "\n"
    )

    # The suggestion typed back, with --provider left as it was.
    again = run_ccr_fetch(
        _fetch_params(monkeypatch, "--provider", "aws", "--service", "gcp-bigquery"),
        client=client,  # type: ignore[arg-type]
    )

    captured = capsys.readouterr()
    assert again == 1
    assert captured.out == ""
    assert captured.err == (
        Fore.RED + "No pack this key can read matches --provider 'aws' and --service "
        "'gcp-bigquery'. gcp-bigquery belongs to gcp, which --provider 'aws' "
        "leaves out." + Fore.RESET + "\n"
    )


def test_main_reports_a_narrowing_no_pack_has_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        remote_cli, "connect", lambda: PackClient(readable_packs("gcp-vertex"))
    )
    argv = ["tmxcaliber", "ccr", "fetch", "--service", "gemini-agent-platform"]
    monkeypatch.setattr(sys, "argv", argv)

    with pytest.raises(SystemExit) as exited:
        cli_module.main()

    captured = capsys.readouterr()
    assert exited.value.code == 1
    assert captured.out == ""
    assert "Did you mean gcp-vertex?" in captured.err


def test_a_refused_archive_is_reported_and_the_other_packs_are_written(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = PackClient(two_packs())
    client.archive_errors["aws-s3"] = ServiceUnavailable(
        "The source archive of aws-s3 does not match its published digest.",
        code="unavailable",
        status=503,
        request_id="r-1",
    )
    params = _fetch_params(monkeypatch, "--out", str(tmp_path))

    status = run_ccr_fetch(params, client=client)  # type: ignore[arg-type]

    captured = capsys.readouterr()
    written = tmp_path / "gcp-bigquery" / "Bigquery.C102" / "metadata.json"
    assert status == 1
    assert captured.out.split() == [str(written)]
    [line] = captured.err.splitlines()
    assert "aws-s3: archive failed: " in line
    assert "unavailable" in line
    assert "request r-1" in line
    assert "No rule matched" not in captured.err


def test_main_runs_fetch_and_exits_with_its_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(remote_cli, "connect", lambda: PackClient(two_packs()))
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", "ccr", "fetch", "aws-nothing"])

    with pytest.raises(SystemExit) as exited:
        cli_module.main()

    assert exited.value.code == 1
    assert "aws-nothing" in capsys.readouterr().err


#: How the API answers for a ThreatModel or a pack this key cannot read.
MISSING = {
    "error": {"code": "not_found", "message": "Not found.", "requestId": "r-404"}
}

#: ``threatmodels list`` as a key that reads two ThreatModels sees it.
THREATMODELS = [
    {
        "tmId": "aws-ec2",
        "title": "Amazon EC2",
        "provider": "aws",
        "service": "ec2",
        "version": "1",
    },
    {
        "tmId": "gcp-bigquery",
        "title": "Google BigQuery",
        "provider": "gcp",
        "service": "bigquery",
        "version": "1",
    },
]

#: ``ccr packs list`` as a key that reads two packs sees it.
PACKS = [
    {"releaseKey": "aws-ec2", "service": "ec2", "ruleCount": 3, "releaseId": None},
    {
        "releaseKey": "gcp-bigquery",
        "service": "bigquery",
        "ruleCount": 1,
        "releaseId": None,
    },
]


def _listing(command: tuple[str, ...], rows: list[dict[str, Any]]) -> FakeResponse:
    """Answer a list command with one page.

    Args:
        command: The list command.
        rows: Its rows.

    Returns:
        The page, holding every field the contract requires of it.
    """
    route = route_for(command)
    assert route is not None
    return FakeResponse(page(route, rows))


def _main_over(
    monkeypatch: pytest.MonkeyPatch, answers: list[Any], argv: list[str]
) -> tuple[int, StrictOpener]:
    """Run the real CLI over a real client whose transport replays answers.

    Args:
        monkeypatch: Replaces argv and the client the CLI connects.
        answers: What the API answers, in order.
        argv: The words after the program name.

    Returns:
        The exit status, and the opener, which recorded each request.
    """
    # Strict, so a name the transport would refuse to send fails here too.
    opener = StrictOpener(answers)
    client = TocClient(client_settings(), opener=opener)
    monkeypatch.setattr(remote_cli, "connect", lambda: client)
    monkeypatch.setattr(sys, "argv", ["tmxcaliber", *argv])
    with pytest.raises(SystemExit) as exited:
        cli_module.main()
    return int(exited.value.code or 0), opener


@pytest.mark.parametrize(
    ("argv", "listing", "rows", "sentence"),
    [
        pytest.param(
            ["ccr", "packs", "get", "aws-ec3"],
            ("ccr", "packs", "list"),
            PACKS,
            "Did you mean aws-ec2?",
            id="ccr packs get",
        ),
        pytest.param(
            ["ccr", "packs", "archive", "aws-ec3", "--output", "unwritten.zip"],
            ("ccr", "packs", "list"),
            PACKS,
            "Did you mean aws-ec2?",
            id="ccr packs archive",
        ),
        pytest.param(
            ["threatmodels", "get", "aws-ec3"],
            ("threatmodels", "list"),
            THREATMODELS,
            "Did you mean aws-ec2 (Amazon EC2)?",
            id="threatmodels get",
        ),
        pytest.param(
            ["threatmodels", "threats", "aws-ec3@1611187200"],
            ("threatmodels", "list"),
            THREATMODELS,
            "Did you mean aws-ec2 (Amazon EC2)?",
            id="pinned threatmodels threats",
        ),
    ],
)
def test_a_name_the_api_does_not_know_is_followed_by_what_it_probably_meant(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    listing: tuple[str, ...],
    rows: list[dict[str, Any]],
    sentence: str,
) -> None:
    status, opener = _main_over(
        monkeypatch, [http_error(404, MISSING), _listing(listing, rows)], argv
    )

    out = capsys.readouterr().out
    assert status == 1
    assert (
        out == Fore.RED + f"Not found. {sentence} (request r-404)" + Fore.RESET + "\n"
    )
    list_route = route_for(listing)
    assert list_route is not None
    assert urllib.parse.urlsplit(opener.requests[1].full_url).path == list_route.path
    assert opener.answers == []


@pytest.mark.parametrize(
    ("argv", "answers"),
    [
        pytest.param(
            ["threatmodels", "get", "aws-ec3"],
            [
                http_error(404, MISSING),
                http_error(
                    403,
                    {
                        "error": {
                            "code": "forbidden",
                            "message": "No.",
                            "requestId": "r-403",
                        }
                    },
                ),
            ],
            id="the list cannot be read",
        ),
        pytest.param(
            ["threatmodels", "get", "azure-cosmosdb"],
            [
                http_error(404, MISSING),
                _listing(("threatmodels", "list"), THREATMODELS),
            ],
            id="nothing is close",
        ),
        pytest.param(
            ["threatmodels", "get", "aws-ec2@1"],
            [
                http_error(404, MISSING),
                _listing(("threatmodels", "list"), THREATMODELS),
            ],
            id="the name is listed, its release is not",
        ),
        pytest.param(
            ["ccr", "packs", "get", "aws-ec3"],
            [http_error(404, MISSING), _listing(("ccr", "packs", "list"), [])],
            id="no pack is readable",
        ),
        pytest.param(["me"], [http_error(404, MISSING)], id="no name was typed"),
    ],
)
def test_a_not_found_with_nothing_to_suggest_is_reported_as_it_was(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    answers: list[Any],
) -> None:
    status, opener = _main_over(monkeypatch, answers, argv)

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED + "Not found. (request r-404)" + Fore.RESET + "\n"
    )
    # A command without a name reads no list, so only its own call was made.
    assert opener.answers == []


def test_the_suggestion_keeps_the_original_errors_details() -> None:
    route = route_for(("threatmodels", "get"))
    assert route is not None
    opener = FakeOpener(
        [http_error(404, MISSING), _listing(("threatmodels", "list"), THREATMODELS)]
    )
    params = Namespace(api_route=route, tm_id="aws-ec3", release="")

    with pytest.raises(NotFound) as caught:
        run_api_command(params, client=TocClient(client_settings(), opener=opener))

    error = caught.value
    assert type(error) is NotFound
    assert (error.code, error.status, error.request_id) == ("not_found", 404, "r-404")
    assert Exception.__str__(error) == ("Not found. Did you mean aws-ec2 (Amazon EC2)?")
    assert isinstance(error.__cause__, NotFound)


def test_the_suggestion_starts_a_sentence_of_its_own() -> None:
    route = route_for(("threatmodels", "get"))
    assert route is not None
    unstopped = {"error": {"code": "not_found", "message": "aws-ec3 is unknown"}}
    opener = FakeOpener(
        [http_error(404, unstopped), _listing(("threatmodels", "list"), THREATMODELS)]
    )
    params = Namespace(api_route=route, tm_id="aws-ec3", release="")

    with pytest.raises(NotFound) as caught:
        run_api_command(params, client=TocClient(client_settings(), opener=opener))

    assert str(caught.value) == (
        "aws-ec3 is unknown. Did you mean aws-ec2 (Amazon EC2)?"
    )


#: ``ccr packs list`` as a key that reads the packs of two renamed services sees it.
VERTEX_PACKS = [
    *PACKS,
    {"releaseKey": "gcp-vertex", "service": "vertex", "ruleCount": 2},
    {"releaseKey": "gcp-pubsub", "service": "pubsub", "ruleCount": 1},
]


def test_fetch_of_a_renamed_pack_typed_with_spaces_still_suggests_its_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The name has spaces in it, which the transport refuses to send, so the
    # pack the user typed never reached the API and no suggestion was made.
    status, opener = _main_over(
        monkeypatch,
        [http_error(404, MISSING), _listing(("ccr", "packs", "list"), VERTEX_PACKS)],
        ["ccr", "fetch", "Gemini Agent Platform"],
    )

    [line] = capsys.readouterr().err.splitlines()
    assert status == 1
    assert line.startswith(Fore.RED + "Gemini Agent Platform: manifest failed: ")
    assert line.endswith("Did you mean gcp-vertex?" + Fore.RESET)
    first = urllib.parse.urlsplit(opener.requests[0].full_url)
    assert first.path == "/v1/ccr/packs/Gemini%20Agent%20Platform"
    assert opener.answers == []


@pytest.mark.parametrize(
    ("argv", "path", "sentence"),
    [
        pytest.param(
            ["ccr", "packs", "get", "vertex ai"],
            "/v1/ccr/packs/vertex%20ai",
            "Did you mean gcp-vertex?",
            id="a renamed pack",
        ),
        pytest.param(
            ["ccr", "packs", "get", "Amazon EC2"],
            "/v1/ccr/packs/Amazon%20EC2",
            "Did you mean aws-ec2?",
            id="a vendor's name",
        ),
        pytest.param(
            ["ccr", "packs", "archive", "pub/sub", "--output", "unwritten.zip"],
            "/v1/ccr/packs/pub%2Fsub/archive",
            "Did you mean gcp-pubsub?",
            id="a slash",
        ),
    ],
)
def test_a_pack_command_given_a_name_with_spaces_answers_not_found_with_a_suggestion(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    path: str,
    sentence: str,
) -> None:
    status, opener = _main_over(
        monkeypatch,
        [http_error(404, MISSING), _listing(("ccr", "packs", "list"), VERTEX_PACKS)],
        argv,
    )

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED + f"Not found. {sentence} (request r-404)" + Fore.RESET + "\n"
    )
    assert urllib.parse.urlsplit(opener.requests[0].full_url).path == path
    assert opener.answers == []


@pytest.mark.parametrize("typed", ["Amazon EC2", "AWS-EC2", "ec 2"])
def test_a_threatmodel_typed_in_a_shape_no_reference_has_is_followed_by_what_it_meant(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], typed: str
) -> None:
    # The reference grammar refuses a name with a space or a capital before any
    # request is made, so there is no 404 to follow and the name was lost.
    status, opener = _main_over(
        monkeypatch,
        [_listing(("threatmodels", "list"), THREATMODELS)],
        ["threatmodels", "get", typed],
    )

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED
        + f"{typed!r} is not a ThreatModel reference; expected provider-service, "
        "optionally with @release. Did you mean aws-ec2 (Amazon EC2)?"
        + Fore.RESET
        + "\n"
    )
    # Only the list was read, because the name could not be sent.
    assert [urllib.parse.urlsplit(r.full_url).path for r in opener.requests] == [
        "/v1/threatmodels"
    ]


#: ``threatmodels list`` as a key that reads ThreatModels from three providers
#: sees it: titles with their short forms in brackets, a service another one
#: also covers, and a title that is the same words under another provider.
OFFICIAL_THREATMODELS = [
    {"tmId": "aws-iam", "title": "AWS Identity and Access Management (IAM)"}
    | {"other_covered_services": ["IAM Access Analyzer"]},
    {"tmId": "aws-kms", "title": "AWS Key Management Service (AWS KMS)"},
    {"tmId": "azure-aks", "title": "Azure Kubernetes Service"},
    {"tmId": "azure-botservice", "title": "Azure Bot Service"},
    {"tmId": "azure-cognitiveservices", "title": "Azure AI services"},
    {"tmId": "azure-recoveryservices", "title": "Azure Recovery Services"},
    {"tmId": "gcp-cloudkms", "title": "Cloud Key Management Service (KMS)"},
    {"tmId": "gcp-iam", "title": "Google Identity and Access Management (IAM)"}
    | {"otherCoveredServices": ["Policy Troubleshooter"]},
]


@pytest.mark.parametrize(
    ("typed", "sentence"),
    [
        pytest.param(
            "Azure Kubernetes Service",
            "Did you mean azure-aks (Azure Kubernetes Service)?",
            id="own title of another provider's service",
        ),
        pytest.param(
            "AWS Key Management Service",
            "Did you mean aws-kms (AWS Key Management Service (AWS KMS))?",
            id="title that an alias leads to another provider with",
        ),
        pytest.param(
            "AWS Key Management Service (AWS KMS)",
            "Did you mean aws-kms (AWS Key Management Service (AWS KMS))?",
            id="whole title",
        ),
        pytest.param(
            "AWS KMS",
            "Did you mean aws-kms (AWS Key Management Service (AWS KMS))?",
            id="short form in brackets",
        ),
        pytest.param(
            "AWS Identity and Access Management (IAM)",
            "Did you mean aws-iam (AWS Identity and Access Management (IAM))?",
            id="whole title with brackets",
        ),
        pytest.param(
            "IAM Access Analyzer",
            "Did you mean aws-iam (AWS Identity and Access Management (IAM))?",
            id="service a ThreatModel also covers",
        ),
        pytest.param(
            "Policy Troubleshooter",
            "Did you mean gcp-iam (Google Identity and Access Management (IAM))?",
            id="service covered, as the API spells the field",
        ),
    ],
)
def test_a_threatmodels_published_name_typed_back_leads_to_it(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    typed: str,
    sentence: str,
) -> None:
    status, _ = _main_over(
        monkeypatch,
        [_listing(("threatmodels", "list"), OFFICIAL_THREATMODELS)],
        ["threatmodels", "get", typed],
    )

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED
        + f"{typed!r} is not a ThreatModel reference; expected provider-service, "
        f"optionally with @release. {sentence}" + Fore.RESET + "\n"
    )


def test_a_threatmodels_key_spelled_like_its_title_leads_to_it_after_the_404(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Well formed, so the API answers 404, and the list is read after it. The
    # typed provider is AWS, so Google's KMS does not come with it.
    status, _ = _main_over(
        monkeypatch,
        [
            http_error(404, MISSING),
            _listing(("threatmodels", "list"), OFFICIAL_THREATMODELS),
        ],
        ["threatmodels", "get", "aws-keymanagementservice"],
    )

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED
        + "Not found. Did you mean aws-kms (AWS Key Management Service (AWS KMS))? "
        "(request r-404)" + Fore.RESET + "\n"
    )


#: ``threatmodels list`` as a key that reads the whole catalogue sees it. A row
#: holds the five fields the contract gives it, and no covered services, so the
#: names a suggestion can use are each title and its short form.
CATALOGUE_ROWS = [
    {
        "tmId": row.tm_id,
        "title": row.title,
        "provider": row.tm_id.partition("-")[0],
        "service": row.tm_id.partition("-")[2],
        "version": "1",
    }
    for row in CATALOGUE
]


@pytest.mark.parametrize(
    ("typed", "sentence"),
    [
        pytest.param(
            "gcp-firestor",
            "Did you mean gcp-firestore (Cloud Firestore), "
            "gcp-filestore (Filestore) or gcp-firebase (Firebase)?",
            id="slip of an id that another title nearly spells",
        ),
        pytest.param(
            "aws-qconnet",
            "Did you mean aws-qconnect (Amazon Q in Connect), "
            "aws-connect (Amazon Connect) or aws-directconnect (AWS Direct Connect)?",
            id="slip of an id that another id nearly spells",
        ),
    ],
)
def test_a_slip_of_an_id_leads_to_its_threatmodel_over_the_whole_catalogue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    typed: str,
    sentence: str,
) -> None:
    # The API answers 404 for a well formed id it does not know, and the list is
    # read after it. Another ThreatModel's title is a near miss of each slip, and
    # the ThreatModel typed has to lead all the same.
    status, _ = _main_over(
        monkeypatch,
        [
            http_error(404, MISSING),
            _listing(("threatmodels", "list"), CATALOGUE_ROWS),
        ],
        ["threatmodels", "get", typed],
    )

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED + f"Not found. {sentence} (request r-404)" + Fore.RESET + "\n"
    )


@pytest.mark.parametrize(
    ("typed", "sentence"),
    [
        pytest.param(
            "Dataproc",
            "Did you mean gcp-dataproc (Managed Service for Apache Spark), "
            "gcp-metastore (Dataproc Metastore) or aws-databrew (AWS Glue DataBrew)?",
            id="service with another title near it",
        ),
        pytest.param(
            "Compute",
            "Did you mean azure-compute (Azure Compute) "
            "or gcp-compute (Compute Engine)?",
            id="service two providers share",
        ),
    ],
)
def test_a_service_typed_alone_leads_to_its_threatmodel_over_the_whole_catalogue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    typed: str,
    sentence: str,
) -> None:
    status, _ = _main_over(
        monkeypatch,
        [_listing(("threatmodels", "list"), CATALOGUE_ROWS)],
        ["threatmodels", "get", typed],
    )

    assert status == 1
    assert capsys.readouterr().out == (
        Fore.RED
        + f"{typed!r} is not a ThreatModel reference; expected provider-service, "
        f"optionally with @release. {sentence}" + Fore.RESET + "\n"
    )


def test_a_malformed_threatmodel_with_nothing_close_is_refused_as_before() -> None:
    route = route_for(("threatmodels", "get"))
    assert route is not None
    opener = FakeOpener([_listing(("threatmodels", "list"), THREATMODELS)])
    params = Namespace(api_route=route, tm_id="Nothing Like It", release="")

    with pytest.raises(ValueError, match="is not a ThreatModel reference"):
        run_api_command(params, client=TocClient(client_settings(), opener=opener))


def test_a_pinned_threatmodel_with_a_bad_release_is_not_read_as_a_misspelled_name() -> (
    None
):
    route = route_for(("threatmodels", "get"))
    assert route is not None
    opener = FakeOpener([])
    params = Namespace(api_route=route, tm_id="aws-ec2@..", release="")

    with pytest.raises(ValueError, match="not a usable release key"):
        run_api_command(params, client=TocClient(client_settings(), opener=opener))

    # The name is listed and right, so the list was never read.
    assert opener.requests == []


@pytest.mark.parametrize("typed", ["", "@1611187200"])
def test_a_threatmodel_with_no_name_in_it_reads_no_list_to_suggest_from(
    typed: str,
) -> None:
    # Nothing was typed that a listed name could be close to.
    route = route_for(("threatmodels", "get"))
    assert route is not None
    opener = FakeOpener([])
    params = Namespace(api_route=route, tm_id=typed, release="")

    with pytest.raises(ValueError, match="is not a ThreatModel reference"):
        run_api_command(params, client=TocClient(client_settings(), opener=opener))

    assert opener.requests == []

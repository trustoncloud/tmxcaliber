"""Source resolution and the API commands, driven through the real CLI."""

from __future__ import annotations

import json
import pathlib
import sys
from argparse import Namespace
from collections.abc import Iterator, Mapping
from typing import Any, NoReturn

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber import remote_cli
from tmxcaliber.lib.remote.config import Settings
from tmxcaliber.lib.remote.contract import route_for
from tmxcaliber.lib.remote.errors import AuthenticationError
from tmxcaliber.lib.remote.resolve import resolve_source
from tmxcaliber.remote_cli import connect, resolve_command_source, run_api_command

from .test_remote_assemble import DETAIL, DFD, PARTS, _at_release
from .test_remote_config import (
    HAZARD,
    NOTED_CASES,
    QUIET_CASES,
    STORED_URL,
    EndpointCase,
)


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

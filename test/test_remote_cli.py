"""Source resolution and the API commands, driven through the real CLI."""

from __future__ import annotations

import json
import pathlib
import sys
from argparse import Namespace
from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber.lib.remote.contract import route_for
from tmxcaliber.lib.remote.resolve import resolve_source
from tmxcaliber.remote_cli import run_api_command

from .test_remote_assemble import DETAIL, DFD, PARTS


class StubClient:
    """Answers the five assembly calls and records them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

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
        if path == "/v1/me":
            return {"tenantId": "t-1", "permissions": ["api.threatmodels.read"]}
        return dict(DETAIL)

    def paginate(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        page_size: int = 0,
    ) -> Iterator[dict[str, Any]]:
        """Answer a collection call.

        Args:
            path: The path.
            params: The query.
            page_size: Ignored.

        Yields:
            Fixture rows.
        """
        self.calls.append((path, dict(params or {})))
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

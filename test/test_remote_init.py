"""`tmxcaliber init`: storing a key, and saying whether it works."""

from __future__ import annotations

import pathlib
from argparse import Namespace
from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from tmxcaliber.lib.remote.config import load_settings
from tmxcaliber.lib.remote.errors import ConfigurationError, NotFound
from tmxcaliber.remote_cli import run_init

KEY = "toc-tak1-" + "A" * 16 + "-" + "B" * 52
OTHER = "toc-tak1-" + "C" * 16 + "-" + "D" * 52


class StubClient:
    """Answers `/v1/me`, or refuses to."""

    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure

    @property
    def base_url(self) -> str:
        """The endpoint.

        Returns:
            A stable fake.
        """
        return "https://api.example.test"

    @property
    def key_id(self) -> str:
        """The credential identity.

        Returns:
            A stable fake.
        """
        return "KEYONE"

    def get(self, path: str, params: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Answer the identity call.

        Args:
            path: The path.
            params: Unused.

        Returns:
            The principal.

        Raises:
            Exception: Whatever this stub was built to raise.
        """
        if self.failure is not None:
            raise self.failure
        return {"tenantId": "t-02370141", "permissions": ["api.threatmodels.read"]}

    def paginate(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        page_size: int = 0,
    ) -> Iterator[dict[str, Any]]:
        """Unused here.

        Args:
            path: The path.
            params: Unused.
            page_size: Unused.

        Yields:
            Nothing.
        """
        yield from ()


def env_for(tmp_path: pathlib.Path, **extra: str) -> dict[str, str]:
    """Build an environment pointing at a throwaway credentials file.

    Args:
        tmp_path: The test's directory.
        **extra: Anything else to set.

    Returns:
        The environment.
    """
    return {"TOC_CONFIG_FILE": str(tmp_path / "credentials"), **extra}


def test_it_writes_a_key_and_verifies_it(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = env_for(tmp_path)

    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    out = capsys.readouterr().out
    assert "readable only by you" in out
    assert "t-02370141" in out
    assert load_settings(env=env).credentials.api_key == KEY


def test_the_key_is_never_printed(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_init(
        Namespace(),
        env=env_for(tmp_path),
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert KEY not in capsys.readouterr().out


def test_an_empty_answer_keeps_the_current_key(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The prompt offers the existing key as the default, so re-running
    # `init` to change only the endpoint must not wipe the credential.
    env = env_for(tmp_path)
    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: "",
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert load_settings(env=env).credentials.api_key == KEY
    # Re-running is also how you see what is set, so the masked key shows.
    assert "toc-tak1-" + "A" * 16 in capsys.readouterr().out


def test_a_first_run_with_no_key_refuses(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ConfigurationError) as caught:
        run_init(
            Namespace(),
            env=env_for(tmp_path),
            read_secret=lambda _: "",
            read_line=lambda _: "",
            interactive=True,
            client=StubClient(),  # type: ignore[arg-type]
        )
    assert "nothing was written" in str(caught.value)


def test_a_piped_key_needs_no_prompt(tmp_path: pathlib.Path) -> None:
    # `echo "$KEY" | tmxcaliber init` has to work in CI, where there is no
    # tty and no one to answer a question about the endpoint.
    env = env_for(tmp_path)

    def refuse(_prompt: str) -> str:
        raise AssertionError("init asked a question with no tty")

    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: KEY,
        read_line=refuse,
        interactive=False,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert load_settings(env=env).credentials.api_key == KEY


def test_it_warns_when_the_environment_shadows_the_file(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # TOC_API_KEY silently wins, so someone who just ran init and still
    # sees the old tenant would otherwise have no way to find out why.
    run_init(
        Namespace(),
        env=env_for(tmp_path, TOC_API_KEY=OTHER),
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert "takes precedence" in capsys.readouterr().out


def test_a_failed_check_does_not_discard_what_was_written(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verification reports, it does not gate.

    A 404 here usually means the API is not enabled for the organization
    yet, which is not a reason to throw away a key that is otherwise fine.
    """
    env = env_for(tmp_path)

    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(NotFound("Not found.", code="not_found")),  # type: ignore[arg-type]
    )

    out = capsys.readouterr().out
    assert "did not work" in out
    assert "not be enabled" in out
    assert load_settings(env=env).credentials.api_key == KEY


def test_an_endpoint_given_at_the_prompt_is_stored(tmp_path: pathlib.Path) -> None:
    env = env_for(tmp_path)

    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: KEY,
        read_line=lambda _: "https://api-staging.example",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert load_settings(env=env).base_url == "https://api-staging.example"


def test_it_repairs_a_file_the_loader_would_refuse(
    tmp_path: pathlib.Path,
) -> None:
    """`init` is the cure the permission refusal points at.

    So it has to be able to read a file the loader rejects, rather than
    failing the same way and leaving no way out.
    """
    env = env_for(tmp_path)
    exposed = tmp_path / "credentials"
    exposed.write_text(f"[default]\napi_key = {OTHER}\n", encoding="utf-8")
    exposed.chmod(0o644)
    with pytest.raises(ConfigurationError):
        load_settings(env=env)

    run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: "",
        read_line=lambda _: "",
        interactive=True,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert exposed.stat().st_mode & 0o777 == 0o600
    assert load_settings(env=env).credentials.api_key == OTHER


def test_it_verifies_the_key_it_stored_not_the_one_in_the_environment(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`init` must test what it wrote.

    Verification used to resolve settings the ordinary way, which prefers
    TOC_API_KEY, so with that variable set it printed "Verified" for a key
    the command had neither written nor tested while the stored one went
    untried.

    **No client is injected here, deliberately.** Injecting one is what hid
    this: it skips the very decision under test. Only the client's
    construction is faked, so the real choice of credential still runs.
    """
    seen: list[str] = []

    class SpyClient:
        def __init__(self, settings: Any) -> None:
            seen.append(settings.credentials.api_key)

        def get(self, path: str, params: Any = None) -> dict[str, Any]:
            return {"tenantId": "t-02370141", "permissions": []}

    monkeypatch.setattr("tmxcaliber.remote_cli.TocClient", SpyClient)

    run_init(
        Namespace(),
        env=env_for(tmp_path, TOC_API_KEY=OTHER),
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=True,
    )

    assert seen == [KEY], "init verified the environment key, not the stored one"


def test_an_endpoint_that_would_leak_the_key_is_refused_before_writing(
    tmp_path: pathlib.Path,
) -> None:
    # Validated before the file is touched, so a bad answer at the prompt
    # does not leave a stored credential pointing somewhere unsafe.
    env = env_for(tmp_path)

    with pytest.raises(ConfigurationError):
        run_init(
            Namespace(),
            env=env,
            read_secret=lambda _: KEY,
            read_line=lambda _: "http://not-localhost.example",
            interactive=True,
        )

    assert not pathlib.Path(env["TOC_CONFIG_FILE"]).exists()


def test_a_failed_check_exits_non_zero(tmp_path: pathlib.Path) -> None:
    """CI must be able to tell a setup that cannot work from one that did.

    The key is still kept, because a failure here is usually the
    organization not being enabled yet rather than a bad key, and making
    the caller re-enter it would help nobody.
    """
    env = env_for(tmp_path)

    code = run_init(
        Namespace(),
        env=env,
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=False,
        client=StubClient(NotFound("Not found.", code="not_found")),  # type: ignore[arg-type]
    )

    assert code == 1
    assert load_settings(env=env).credentials.api_key == KEY


def test_a_successful_check_exits_zero(tmp_path: pathlib.Path) -> None:
    code = run_init(
        Namespace(),
        env=env_for(tmp_path),
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=False,
        client=StubClient(),  # type: ignore[arg-type]
    )

    assert code == 0


def test_it_verifies_the_endpoint_commands_will_use(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOC_API_URL wins here exactly as it does for every other command.

    Taking only the stored value meant init checked one API while later
    commands called another, which is the failure the endpoint precedence
    fix was meant to end and did not finish ending.
    """
    checked: list[str] = []

    class SpyClient:
        def __init__(self, settings: Any) -> None:
            checked.append(settings.base_url)

        def get(self, path: str, params: Any = None) -> dict[str, Any]:
            return {"tenantId": "t-1", "permissions": []}

    monkeypatch.setattr("tmxcaliber.remote_cli.TocClient", SpyClient)

    run_init(
        Namespace(),
        env=env_for(tmp_path, TOC_API_URL="https://api.example.com"),
        read_secret=lambda _: KEY,
        read_line=lambda _: "",
        interactive=False,
    )

    assert checked == ["https://api.example.com"]

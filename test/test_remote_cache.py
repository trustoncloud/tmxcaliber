"""The cache path, and the release values that must never reach it.

A release becomes a filename. `pathlib` discards everything to the left of
an absolute component, so an unchecked release is not a cosmetic problem:
it is an arbitrary-write primitive driven by whatever the API returned.
"""

from __future__ import annotations

import pathlib

import pytest

from tmxcaliber.lib.remote.cache import cached_path, read, write
from tmxcaliber.lib.remote.ref import TmRef, is_release

REF = TmRef("aws", "s3")


def env_for(tmp_path: pathlib.Path) -> dict[str, str]:
    """Point the cache at a throwaway directory.

    Args:
        tmp_path: The test's directory.

    Returns:
        The environment.
    """
    return {"TMXCALIBER_CACHE_DIR": str(tmp_path / "cache")}


@pytest.mark.parametrize(
    "release",
    [
        "/tmp/target",
        "../../../../../../tmp/evil",
        "..",
        ".",
        "a/b",
        "",
        "-rf",
        ".hidden",
    ],
)
def test_a_release_that_could_act_as_a_path_is_refused(
    release: str, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(ValueError):
        cached_path(REF, release, "https://api.example", "K", env_for(tmp_path))


@pytest.mark.parametrize("release", ["1611187200", "20240423", "v1.2.3", "latest"])
def test_an_ordinary_release_is_accepted(release: str, tmp_path: pathlib.Path) -> None:
    path = cached_path(REF, release, "https://api.example", "K", env_for(tmp_path))

    assert path.name == f"{release}.json"


def test_the_path_stays_inside_the_cache(tmp_path: pathlib.Path) -> None:
    env = env_for(tmp_path)
    root = pathlib.Path(env["TMXCALIBER_CACHE_DIR"]).resolve()

    path = cached_path(REF, "1611187200", "https://api.example", "K", env)

    assert path.resolve().is_relative_to(root)


def test_the_endpoint_and_the_credential_both_partition(
    tmp_path: pathlib.Path,
) -> None:
    env = env_for(tmp_path)
    here = cached_path(REF, "1", "https://api.example", "KEYONE", env)

    assert here != cached_path(REF, "1", "https://other.example", "KEYONE", env)
    assert here != cached_path(REF, "1", "https://api.example", "KEYTWO", env)


def test_a_write_is_atomic_and_leaves_nothing_behind(
    tmp_path: pathlib.Path,
) -> None:
    # An interrupted write must not be read later as a complete document.
    path = cached_path(REF, "1", "https://api.example", "K", env_for(tmp_path))

    write(path, {"metadata": {}})

    assert read(path, max_age=None) == {"metadata": {}}
    assert list(path.parent.glob("*.part")) == []


def test_a_damaged_entry_is_a_miss_rather_than_an_error(
    tmp_path: pathlib.Path,
) -> None:
    # The document can always be fetched again, so a broken entry is never
    # worth stopping for.
    path = cached_path(REF, "1", "https://api.example", "K", env_for(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json", encoding="utf-8")

    assert read(path, max_age=None) is None


@pytest.mark.parametrize(
    ("value", "safe"),
    [
        ("1611187200", True),
        ("20240423", True),
        ("v1", True),
        ("/abs", False),
        ("../up", False),
        ("..", False),
        ("", False),
    ],
)
def test_the_release_grammar_has_one_owner(value: str, safe: bool) -> None:
    # Used for the release a caller types and the one the server returns,
    # which is the asymmetry that let this through: the reference grammar
    # already excluded a slash, so only the server side was unguarded.
    assert is_release(value) is safe

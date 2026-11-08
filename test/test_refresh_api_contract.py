"""The script the daily contract refresh runs.

It decides whether a release happens at all, and a release publishes to PyPI,
which cannot be undone. So the cases worth breaking on purpose are the ones that
would cut a release they should not: a gateway error page taken for a contract,
a formatting difference taken for a change, and a version bump that rewrites
the wrong line.

Follows Arrange-Act-Assert.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tmxcaliber.lib.remote import contract

_SCRIPT = (
    Path(__file__).resolve().parents[1] / ".github/scripts/refresh_api_contract.py"
)
_REPO = _SCRIPT.parents[2]


def _load() -> ModuleType:
    """Import the script, which is not part of the package."""
    spec = importlib.util.spec_from_file_location("refresh_api_contract", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


refresh = _load()


def _document(**paths: Any) -> dict[str, Any]:
    """A minimal contract publishing the given paths."""
    return {
        "openapi": "3.1.0",
        "info": {"title": "API"},
        "paths": paths or {"/v1/me": {}},
    }


def _raw(document: Any, **dumps: Any) -> bytes:
    return json.dumps(document, **dumps).encode()


PYPROJECT = """\
[build-system]
requires = ["setuptools"]

[project]
name = "tmxcaliber"
version = "0.10.0"
dependencies = []

[tool.other]
version = "0.10.0"
"""


# --- the contract --------------------------------------------------------------


def test_the_vendored_path_is_the_one_the_package_reads() -> None:
    """The script cannot import the package, so its path is pinned here."""
    expected = Path(*contract.CONTRACT_PACKAGE.split(".")) / contract.CONTRACT_FILE

    assert expected == refresh.CONTRACT_PATH
    assert (_REPO / refresh.CONTRACT_PATH).is_file()


def test_the_vendored_copy_is_itself_a_contract() -> None:
    raw = (_REPO / refresh.CONTRACT_PATH).read_bytes()

    document = refresh.parse_contract(raw)

    assert document["paths"]


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"<html><body>502 Bad Gateway</body></html>", "not JSON"),
        (b"", "not JSON"),
        (_raw([1, 2]), "not a JSON object"),
        (_raw({"swagger": "2.0", "paths": {"/a": {}}}), "not an OpenAPI 3"),
        (_raw({"openapi": "3.1.0", "paths": {}}), "no paths"),
        (_raw({"openapi": "3.1.0"}), "no paths"),
    ],
)
def test_anything_but_a_contract_is_refused(body: bytes, reason: str) -> None:
    with pytest.raises(refresh.ContractError, match=reason):
        refresh.parse_contract(body)


def test_the_same_contract_is_unchanged() -> None:
    raw = _raw(_document())

    assert refresh.contract_changed(raw, raw) is False


def test_formatting_alone_is_not_a_change() -> None:
    """A release on whitespace or key order would publish nothing new."""
    vendored = _raw(_document(), indent=2)
    fetched = _raw(_document(), sort_keys=True, separators=(",", ":"))

    assert refresh.contract_changed(fetched, vendored) is False


def test_a_new_path_is_a_change() -> None:
    vendored = _raw(_document(**{"/v1/me": {}}))
    fetched = _raw(_document(**{"/v1/me": {}, "/v1/apis": {}}))

    assert refresh.contract_changed(fetched, vendored) is True


def test_a_changed_description_is_a_change() -> None:
    vendored = _raw(_document(**{"/v1/me": {"get": {"summary": "Old."}}}))
    fetched = _raw(_document(**{"/v1/me": {"get": {"summary": "New."}}}))

    assert refresh.contract_changed(fetched, vendored) is True


def test_an_error_page_is_never_compared() -> None:
    with pytest.raises(refresh.ContractError):
        refresh.contract_changed(b"Service Unavailable", _raw(_document()))


# --- the version ---------------------------------------------------------------


def test_the_patch_number_is_incremented() -> None:
    text, version = refresh.bump_patch(PYPROJECT)

    assert version == "0.10.1"
    assert 'version = "0.10.1"' in text


def test_only_the_project_version_line_moves() -> None:
    """Another table's `version` key must survive untouched."""
    text, _ = refresh.bump_patch(PYPROJECT)

    changed = [
        (old, new)
        for old, new in zip(PYPROJECT.splitlines(), text.splitlines(), strict=True)
        if old != new
    ]
    assert changed == [('version = "0.10.0"', 'version = "0.10.1"')]


def test_the_repository_pyproject_bumps_cleanly() -> None:
    text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")

    bumped, version = refresh.bump_patch(text)

    assert (
        sum(a != b for a, b in zip(text.splitlines(), bumped.splitlines(), strict=True))
        == 1
    )
    assert version.count(".") == 2


@pytest.mark.parametrize("version", ["1.0", "1.0.0rc1", "v1.0.0"])
def test_a_version_that_is_not_major_minor_patch_is_refused(version: str) -> None:
    with pytest.raises(ValueError, match=r"MAJOR\.MINOR\.PATCH"):
        refresh.bump_patch(
            PYPROJECT.replace('"0.10.0"\ndependencies', f'"{version}"\ndependencies')
        )


def test_a_dynamic_version_is_refused() -> None:
    text = PYPROJECT.replace(
        'version = "0.10.0"\ndependencies', 'dynamic = ["version"]\ndependencies'
    )

    with pytest.raises(ValueError, match="no static version"):
        refresh.bump_patch(text)


# --- the command line ----------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository root holding a vendored contract and a pyproject."""
    (tmp_path / refresh.CONTRACT_PATH).parent.mkdir(parents=True)
    (tmp_path / refresh.CONTRACT_PATH).write_bytes(_raw(_document()))
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_compare_prints_whether_the_contract_changed(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fetched = repo / "fetched.json"
    fetched.write_bytes(_raw(_document(**{"/v1/me": {}, "/v1/apis": {}})))

    status = refresh.main(["compare", str(fetched)])

    assert status == 0
    assert capsys.readouterr().out.strip() == "true"


def test_apply_writes_the_fetched_bytes_as_served(repo: Path) -> None:
    served = _raw(_document(**{"/v1/apis": {}}), indent=2)
    fetched = repo / "fetched.json"
    fetched.write_bytes(served)

    refresh.main(["apply", str(fetched)])

    assert (repo / refresh.CONTRACT_PATH).read_bytes() == served


def test_apply_leaves_the_copy_alone_when_the_body_is_not_a_contract(
    repo: Path,
) -> None:
    before = (repo / refresh.CONTRACT_PATH).read_bytes()
    fetched = repo / "fetched.json"
    fetched.write_bytes(b"Bad Gateway")

    with pytest.raises(refresh.ContractError):
        refresh.main(["apply", str(fetched)])

    assert (repo / refresh.CONTRACT_PATH).read_bytes() == before


def test_bump_rewrites_pyproject_and_prints_the_version(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = refresh.main(["bump"])

    assert status == 0
    assert capsys.readouterr().out.strip() == "0.10.1"
    assert 'version = "0.10.1"' in (repo / "pyproject.toml").read_text(encoding="utf-8")


def test_an_unknown_command_is_a_usage_error(repo: Path) -> None:
    assert refresh.main(["release"]) == 2


# --- the lockfile --------------------------------------------------------------

LOCK = """\
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "beautifulsoup4"
version = "4.13.4"

[[package]]
name = "tmxcaliber"
version = "0.10.0"
source = { editable = "." }
"""

RELOCKED = LOCK.replace(
    'name = "tmxcaliber"\nversion = "0.10.0"', 'name = "tmxcaliber"\nversion = "0.10.1"'
)


def test_a_relock_that_moves_only_the_version_line_passes() -> None:
    refresh.check_lock(LOCK, RELOCKED, "tmxcaliber", "0.10.1")


@pytest.mark.parametrize(
    ("after", "reason"),
    [
        # What the unpinned uv did to the first refresh PR.
        (RELOCKED.replace("revision = 3", "revision = 5"), "on 2 lines"),
        (RELOCKED.replace('version = "4.13.4"', 'version = "4.14.0"'), "on 2 lines"),
        (RELOCKED + '\n[[package]]\nname = "new"\n', "went from"),
        (LOCK, "on 0 lines"),
    ],
    ids=[
        "new lockfile revision",
        "dependency resolved again",
        "lines added",
        "unchanged",
    ],
)
def test_a_relock_that_rewrites_more_is_refused(after: str, reason: str) -> None:
    with pytest.raises(refresh.LockChurnError, match=reason):
        refresh.check_lock(LOCK, after, "tmxcaliber", "0.10.1")


def test_another_packages_version_line_is_not_the_bump() -> None:
    after = LOCK.replace('version = "4.13.4"', 'version = "4.14.0"')

    with pytest.raises(refresh.LockChurnError, match="not tmxcaliber's version line"):
        refresh.check_lock(LOCK, after, "tmxcaliber", "0.10.1")


def test_the_version_line_must_carry_the_new_version() -> None:
    after = LOCK.replace(
        'name = "tmxcaliber"\nversion = "0.10.0"',
        'name = "tmxcaliber"\nversion = "0.10.2"',
    )

    with pytest.raises(refresh.LockChurnError, match=r"carrying 0\.10\.1"):
        refresh.check_lock(LOCK, after, "tmxcaliber", "0.10.1")


def test_the_repository_lockfile_has_the_shape_the_check_reads() -> None:
    """The root entry's version line follows its name line in the real file."""
    pyproject = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    name, version = pyproject["project"]["name"], pyproject["project"]["version"]
    before = (_REPO / "uv.lock").read_text(encoding="utf-8")
    after = before.replace(
        f'name = "{name}"\nversion = "{version}"', f'name = "{name}"\nversion = "9.9.9"'
    )

    refresh.check_lock(before, after, name, "9.9.9")


def test_check_lock_reads_the_bumped_pyproject(repo: Path) -> None:
    (repo / "uv.lock").write_text(RELOCKED, encoding="utf-8")
    before = repo / "uv.lock.before"
    before.write_text(LOCK, encoding="utf-8")
    refresh.main(["bump"])

    assert refresh.main(["check-lock", str(before)]) == 0


def test_check_lock_stops_on_churn(repo: Path) -> None:
    (repo / "uv.lock").write_text(
        RELOCKED.replace("revision = 3", "revision = 5"), encoding="utf-8"
    )
    before = repo / "uv.lock.before"
    before.write_text(LOCK, encoding="utf-8")
    refresh.main(["bump"])

    with pytest.raises(refresh.LockChurnError):
        refresh.main(["check-lock", str(before)])

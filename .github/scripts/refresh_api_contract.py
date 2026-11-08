"""Refresh the vendored API contract from the one the API serves.

Run by ``.github/workflows/refresh-api-contract.yml``. Standard library only, and
it never imports ``tmxcaliber``: two of that workflow's jobs hold a credential,
and a job holding a credential installs nothing.

Usage::

    python refresh_api_contract.py compare FETCHED   # prints true or false
    python refresh_api_contract.py apply FETCHED     # writes the vendored copy
    python refresh_api_contract.py bump              # bumps the patch version
    python refresh_api_contract.py check-lock BEFORE # uv.lock moved one line only
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

#: The vendored copy, relative to the repository root. A second spelling of
#: ``CONTRACT_PACKAGE`` and ``CONTRACT_FILE`` in ``lib/remote/contract.py``, which
#: this script cannot import; ``test_refresh_api_contract.py`` pins the two.
CONTRACT_PATH = Path("tmxcaliber/lib/remote/openapi/v1.json")

PYPROJECT_PATH = Path("pyproject.toml")

LOCK_PATH = Path("uv.lock")

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_TABLE = re.compile(r"^\[[^\]]+\]\s*$", re.MULTILINE)


class ContractError(ValueError):
    """The fetched document is not a contract this package could vendor."""


class LockChurnError(ValueError):
    """Relocking rewrote more of ``uv.lock`` than the root package's version."""


def parse_contract(raw: bytes) -> dict[str, Any]:
    """Parse a fetched contract and refuse anything that is not one.

    A gateway error page or an empty body must never replace the vendored
    copy, so the document has to be an OpenAPI 3 object publishing paths.

    Args:
        raw: The response body.

    Returns:
        The parsed document.

    Raises:
        ContractError: When the body is not JSON, or not an OpenAPI 3 document
            with at least one path.

    """
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ContractError(f"the body is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ContractError("the body is not a JSON object")
    if not str(document.get("openapi", "")).startswith("3."):
        raise ContractError("the body is not an OpenAPI 3 document")
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ContractError("the document publishes no paths")
    return document


def contract_changed(fetched: bytes, vendored: bytes) -> bool:
    """Whether the fetched contract says something the vendored one does not.

    Compared as parsed JSON, so formatting alone never cuts a release.

    Args:
        fetched: The contract the API served.
        vendored: The copy this package ships.

    Returns:
        True when the two documents differ.

    Raises:
        ContractError: When the fetched document is not a contract.

    """
    return bool(parse_contract(fetched) != json.loads(vendored))


def bump_patch(pyproject: str) -> tuple[str, str]:
    """Increment the patch number of ``[project].version``.

    Only the ``version`` line inside the ``[project]`` table is rewritten, so a
    ``version`` key in any other table is never touched, and the result is
    parsed back to prove it says what was intended.

    Args:
        pyproject: The text of ``pyproject.toml``.

    Returns:
        The rewritten text and the new version.

    Raises:
        ValueError: When ``[project]`` declares no static version, the version
            is not ``MAJOR.MINOR.PATCH``, or the table does not hold exactly one
            ``version`` line.

    """
    current = tomllib.loads(pyproject).get("project", {}).get("version")
    if not isinstance(current, str):
        raise ValueError("[project] declares no static version")
    match = _VERSION.match(current)
    if match is None:
        raise ValueError(f"version {current!r} is not MAJOR.MINOR.PATCH")
    major, minor, patch = (int(part) for part in match.groups())
    new = f"{major}.{minor}.{patch + 1}"

    start = pyproject.index("[project]\n")
    following = _TABLE.search(pyproject, start + len("[project]\n"))
    end = following.start() if following else len(pyproject)
    table = pyproject[start:end]
    line = re.compile(rf'^version\s*=\s*"{re.escape(current)}"\s*$', re.MULTILINE)
    rewritten, count = line.subn(f'version = "{new}"', table)
    if count != 1:
        raise ValueError(f"[project] holds {count} version lines, expected 1")

    result = pyproject[:start] + rewritten + pyproject[end:]
    if tomllib.loads(result)["project"]["version"] != new:
        raise ValueError("the rewritten pyproject.toml does not carry the new version")
    return result, new


def check_lock(before: str, after: str, package: str, version: str) -> None:
    """Hold a relock to the one line a version bump moves.

    The lockfile records the root package's own version, so a patch bump moves
    that line and nothing else. Anything more is uv rewriting the file, with a
    newer lockfile revision or a dependency resolved again, and a release must
    not carry either unnoticed. The workflow pins uv against the first; this
    catches whatever the pin does not.

    Args:
        before: ``uv.lock`` as it was before relocking.
        after: ``uv.lock`` as relocking left it.
        package: ``[project].name``, whose entry holds the version line.
        version: The new ``[project].version``.

    Raises:
        LockChurnError: When any line other than that package's version line
            changed, lines were added or removed, or the version line does not
            carry ``version``.

    """
    old, new = before.splitlines(), after.splitlines()
    if len(old) != len(new):
        raise LockChurnError(
            f"uv.lock went from {len(old)} to {len(new)} lines; "
            "only the version line may change"
        )
    changed = [
        index for index, (a, b) in enumerate(zip(old, new, strict=True)) if a != b
    ]
    if len(changed) != 1:
        raise LockChurnError(
            f"uv.lock changed on {len(changed)} lines; only the version line may change"
        )
    (index,) = changed
    if (
        index == 0
        or new[index - 1] != f'name = "{package}"'
        or new[index] != f'version = "{version}"'
    ):
        raise LockChurnError(
            f"uv.lock line {index + 1} changed, and it is not {package}'s version "
            f"line carrying {version}"
        )


def main(argv: list[str]) -> int:
    """Run one subcommand from the repository root.

    Args:
        argv: The arguments after the script name.

    Returns:
        The exit status.

    """
    if argv[:1] == ["compare"] and len(argv) == 2:
        changed = contract_changed(
            Path(argv[1]).read_bytes(), CONTRACT_PATH.read_bytes()
        )
        print("true" if changed else "false")
        return 0
    if argv[:1] == ["apply"] and len(argv) == 2:
        fetched = Path(argv[1]).read_bytes()
        parse_contract(fetched)
        CONTRACT_PATH.write_bytes(fetched)
        return 0
    if argv == ["bump"]:
        text, version = bump_patch(PYPROJECT_PATH.read_text(encoding="utf-8"))
        PYPROJECT_PATH.write_text(text, encoding="utf-8")
        print(version)
        return 0
    if argv[:1] == ["check-lock"] and len(argv) == 2:
        project = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))["project"]
        check_lock(
            Path(argv[1]).read_text(encoding="utf-8"),
            LOCK_PATH.read_text(encoding="utf-8"),
            str(project["name"]),
            str(project["version"]),
        )
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Check the public names declared by the vendored OpenAPI contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Final

CONTRACT_PATH: Final[Path] = Path(__file__).parent / "openapi" / "v1.json"
PUBLIC_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-z][A-Za-z0-9]*$")
CANONICAL_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
PATH_PARAMETER: Final[re.Pattern[str]] = re.compile(r"\{([^{}]+)\}")


def _check_public_name(name: object, location: str, violations: list[str]) -> None:
    if not isinstance(name, str) or PUBLIC_NAME.fullmatch(name) is None:
        violations.append(f"{location}: {name!r} must be camelCase")


def _walk(node: object, location: str, violations: list[str]) -> None:
    if isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, f"{location}[{index}]", violations)
        return
    if not isinstance(node, dict):
        return

    properties = node.get("properties")
    if isinstance(properties, dict):
        for name in properties:
            _check_public_name(name, f"{location}.properties", violations)

    required = node.get("required")
    if isinstance(required, list):
        for index, name in enumerate(required):
            _check_public_name(name, f"{location}.required[{index}]", violations)

    parameter_location = node.get("in")
    if parameter_location in ("path", "query"):
        _check_public_name(
            node.get("name"), f"{location} {parameter_location} parameter", violations
        )

    canonical_name = node.get("x-canonical-name")
    if "x-canonical-name" in node and (
        not isinstance(canonical_name, str)
        or CANONICAL_NAME.fullmatch(canonical_name) is None
    ):
        violations.append(
            f"{location}.x-canonical-name: {canonical_name!r} must be snake_case"
        )
    if node.get("x-defined-by") == "canonical-schema" and canonical_name is None:
        violations.append(f"{location}: canonical-schema field needs x-canonical-name")

    for key, value in node.items():
        if isinstance(key, str) and key not in ("example", "examples"):
            _walk(value, f"{location}.{key}", violations)


def naming_violations(document: object) -> list[str]:
    """Find names that break the contract's wire and canonical casing rules.

    Args:
        document: The parsed OpenAPI document.

    Returns:
        Locations of invalid JSON properties, required fields, path or query
        parameters, path placeholders, and canonical source names.
    """
    violations: list[str] = []
    _walk(document, "$", violations)
    if isinstance(document, dict):
        paths = document.get("paths")
        if isinstance(paths, dict):
            for path in paths:
                if isinstance(path, str):
                    for name in PATH_PARAMETER.findall(path):
                        _check_public_name(name, f"$.paths[{path!r}]", violations)
    return sorted(violations)


def main() -> int:
    """Validate the packaged contract and return a CI-friendly exit status.

    Returns:
        Zero when all names follow their casing rules, one otherwise.
    """
    with CONTRACT_PATH.open(encoding="utf-8") as source:
        document = json.load(source)
    violations = naming_violations(document)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        return 1
    print("Vendored OpenAPI field and parameter names follow the naming rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

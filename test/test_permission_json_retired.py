"""Tests for how the permission validator skips retired threats.

A retired threat's ``access`` tree is not validated. The flag used to be the
Sheet text ``"true"`` and is now a JSON boolean; both must skip, and every
live form must still be validated.
"""

from typing import Any

import pytest

from tmxcaliber.lib.permission_json import validate_permissions

#: A top-level list is an E65 violation, so a validated threat always yields
#: exactly one finding and a skipped threat yields none.
MALFORMED_ACCESS: list[str] = ["s3:GetObject"]


def _threat(**fields: Any) -> dict[str, Any]:
    return {"id": "S.T1", "access": MALFORMED_ACCESS, **fields}


@pytest.mark.parametrize("retired", [True, "true", "TRUE", " true "])
def test_a_retired_threat_is_skipped(retired: object) -> None:
    # Arrange
    threats = [_threat(retired=retired)]

    # Act
    violations = validate_permissions(threats)

    # Assert
    assert violations == []


@pytest.mark.parametrize("retired", [False, "false", "FALSE", ""])
def test_a_live_threat_is_validated(retired: object) -> None:
    # Arrange
    threats = [_threat(retired=retired)]

    # Act
    violations = validate_permissions(threats)

    # Assert
    assert [v.rule_id for v in violations] == ["E65"]


def test_a_threat_without_a_flag_is_validated() -> None:
    # Arrange
    threats = [_threat()]

    # Act
    violations = validate_permissions(threats)

    # Assert
    assert [v.rule_id for v in violations] == ["E65"]

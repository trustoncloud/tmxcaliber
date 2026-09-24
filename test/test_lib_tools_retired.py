"""Tests for the one reading of a ThreatModel entity's ``retired`` flag.

The flag has been a Sheet string (``"true"``/``"false"``), is now a JSON
boolean, and is absent on older feature classes and actions. The released
dataset also keeps retired ids as ``{"retired": true}`` stubs.
"""

from typing import Any

import pytest

from tmxcaliber.lib.tools import (
    RETIRABLE_SECTIONS,
    drop_retired_stubs,
    is_retired,
    is_retired_stub,
)


def test_the_five_entity_sections_are_retirable() -> None:
    # Arrange
    expected = {
        "feature_classes",
        "threats",
        "control_objectives",
        "controls",
        "actions",
    }

    # Act
    sections = set(RETIRABLE_SECTIONS)

    # Assert
    assert sections == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("TRUE", True),
        (" True ", True),
        ("false", False),
        ("FALSE", False),
        ("", False),
        ("yes", False),
        (None, False),
        (1, False),
        (0, False),
        ([], False),
    ],
)
def test_is_retired_reads_every_vintage(value: object, expected: bool) -> None:
    # Arrange / Act
    result = is_retired(value)

    # Assert
    assert result is expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"retired": True}, True),
        ({"retired": "true"}, True),
        ({"retired": False}, False),
        ({"retired": "false"}, False),
        ({"retired": True, "name": "n"}, False),
        ({}, False),
        ("S3.FC1", False),
        (None, False),
    ],
)
def test_is_retired_stub_needs_a_lone_retired_flag(
    entry: object, expected: bool
) -> None:
    # Arrange / Act
    result = is_retired_stub(entry)

    # Assert
    assert result is expected


def test_drop_retired_stubs_keeps_live_entries_in_order_and_copies() -> None:
    # Arrange
    section: dict[str, Any] = {
        "S.T3": {"name": "c", "retired": False},
        "S.T1": {"retired": True},
        "S.T2": {"name": "b", "retired": True},
    }

    # Act
    live = drop_retired_stubs(section)

    # Assert
    assert list(live) == ["S.T3", "S.T2"]
    assert "S.T1" in section
    assert live is not section

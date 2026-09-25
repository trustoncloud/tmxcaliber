"""Tests for loading a ThreatModel that carries stubs or string flags.

The internal SDK serves released-dataset documents, where a retired id is kept
as ``{"retired": true}`` and nothing else, to readers that load them through
:class:`ThreatModelData`. Older documents carry ``"true"``/``"false"``. Every
reader downstream of the load expects live, fully populated entities.
"""

import csv
import io
from collections.abc import Iterator
from typing import Any

import pytest

from tmxcaliber.lib.threatmodel_data import (
    ThreatModelData,
    ThreatModelDataList,
    upgrade_to_latest_template_version,
)
from tmxcaliber.lib.tools import RETIRABLE_SECTIONS

STUB: dict[str, Any] = {"retired": True}


@pytest.fixture(autouse=True)
def _isolated_data_list(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(ThreatModelData, "threatmodel_data_list", [])
    yield


def _released_document() -> dict[str, Any]:
    """A released-dataset document with one stub in every section."""
    return {
        "metadata": {"release": "1627750800", "version": "20260925"},
        "feature_classes": {
            "S.FC1": {"name": "Root", "class_relationship": [], "retired": False},
            "S.FC2": {
                "name": "Child",
                "class_relationship": [{"type": "parent", "class": "S.FC1"}],
                "retired": False,
            },
            "S.FC3": STUB,
        },
        "threats": {
            "S.T1": {
                "feature_class": "S.FC1",
                "name": "Live",
                "access": {"UNIQUE": "s:Get"},
                "retired": False,
            },
            "S.T2": STUB,
        },
        "control_objectives": {
            "S.CO1": {"description": "co", "scf": ["IAC-01"], "retired": False},
            "S.CO2": STUB,
        },
        "controls": {
            "S.C1": {
                "objective": "S.CO1",
                "description": "c",
                "feature_class": ["S.FC1"],
                "mitigate": [{"threat": "S.T1"}],
                "retired": False,
            },
            "S.C2": STUB,
        },
        "actions": {
            "S.A1": {"api": "Get", "feature_class": "S.FC1", "retired": False},
            "S.A2": STUB,
        },
    }


# ------------------------------------------------------------------ stubs


def test_stubs_are_dropped_from_every_section() -> None:
    # Arrange
    document = _released_document()

    # Act
    tm = ThreatModelData(document)

    # Assert
    loaded = tm.get_json()
    assert {section: sorted(loaded[section]) for section in RETIRABLE_SECTIONS} == {
        "feature_classes": ["S.FC1", "S.FC2"],
        "threats": ["S.T1"],
        "control_objectives": ["S.CO1"],
        "controls": ["S.C1"],
        "actions": ["S.A1"],
    }


def test_a_stub_is_not_reported_as_removed_output() -> None:
    # Arrange
    tm = ThreatModelData(_released_document())

    # Act
    removed = tm.get_removed_output()

    # Assert
    assert removed == {}


def test_the_feature_class_hierarchy_loads_without_stubs() -> None:
    # Arrange
    tm = ThreatModelData(_released_document())

    # Act
    ancestors = tm.get_ancestors_feature_classes("S.FC2")

    # Assert
    assert ancestors == ["s.fc1"]


def test_get_csv_works_on_a_document_that_had_stubs() -> None:
    # Arrange
    tm = ThreatModelData(_released_document())

    # Act
    output = ThreatModelDataList([tm]).get_csv()

    # Assert
    rows = list(csv.DictReader(io.StringIO(output.getvalue())))
    assert [row["id"] for row in rows] == ["S.T1"]
    assert rows[0]["retired"] == "False"


def test_the_controls_csv_lists_only_live_controls() -> None:
    # Arrange
    ThreatModelData(_released_document())

    # Act
    matrix = ThreatModelData.get_csv_of_controls()

    # Assert
    assert [row[2] for row in matrix[1:]] == ["S.C1"]


# ---------------------------------------------------------- string flags


def test_string_flags_become_booleans() -> None:
    # Arrange: a document from before the boolean change, including a retired
    # control that leaked as a full record because a live control needs it.
    document: dict[str, Any] = {
        "threats": {"S.T1": {"name": "t", "retired": "false"}},
        "control_objectives": {"S.CO1": {"description": "co", "retired": "FALSE"}},
        "controls": {
            "S.C1": {"description": "live", "retired": "false"},
            "S.C2": {"description": "leaked", "retired": " true "},
        },
    }

    # Act
    tm = ThreatModelData(document)

    # Assert
    assert tm.threats["S.T1"]["retired"] is False
    assert tm.control_objectives["S.CO1"]["retired"] is False
    assert tm.controls["S.C1"]["retired"] is False
    assert tm.controls["S.C2"]["retired"] is True


def test_a_string_stub_is_dropped_too() -> None:
    # Arrange
    document: dict[str, Any] = {"controls": {"S.C1": {"retired": "true"}}}

    # Act
    tm = ThreatModelData(document)

    # Assert
    assert tm.controls == {}


def test_an_absent_flag_stays_absent() -> None:
    # Arrange
    document: dict[str, Any] = {
        "feature_classes": {"S.FC1": {"name": "fc", "class_relationship": []}},
        "actions": {"S.A1": {"api": "Get"}},
    }

    # Act
    tm = ThreatModelData(document)

    # Assert
    assert "retired" not in tm.feature_classes["S.FC1"]
    assert "retired" not in tm.actions["S.A1"]


# ------------------------------------------------------- class_relationship


def test_a_feature_class_without_class_relationship_does_not_raise() -> None:
    # Arrange
    document: dict[str, Any] = {
        "feature_classes": {
            "S.FC1": {"name": "no relationship key"},
            "S.FC2": {"name": "legacy", "class_relationship": {}},
        }
    }

    # Act
    tm = ThreatModelData(document)

    # Assert
    assert "class_relationship" not in tm.feature_classes["S.FC1"]
    assert tm.feature_classes["S.FC2"]["class_relationship"] == []
    assert tm.get_ancestors_feature_classes("S.FC2") == []


# ------------------------------------------------------------- contract


def test_upgrade_mutates_in_place_and_returns_the_same_object() -> None:
    # Arrange
    document = _released_document()
    threats = document["threats"]

    # Act
    upgraded = upgrade_to_latest_template_version(document)

    # Assert
    assert upgraded is document
    assert upgraded["threats"] is threats
    assert "S.T2" not in threats

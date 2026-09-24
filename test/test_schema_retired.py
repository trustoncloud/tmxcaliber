"""Tests for the ``retired`` flag and stub shape in the ThreatModel schema.

From schema 20260925 every entity in the five retirable sections is exactly
one of: a live, fully populated record carrying ``"retired": <boolean>``, or a
``{"retired": true}`` stub keyed by id (released dataset only).
"""

import copy
from importlib.resources import files
from typing import Any

import pytest

from tmxcaliber.lib.tools import RETIRABLE_SECTIONS
from tmxcaliber.schema import schema as schema_mod
from tmxcaliber.schema.schema import (
    SchemaValidationError,
    validate_threatmodel_schema,
)

#: The pointer tmx's detector E136 validates ``api_details`` cells against.
#: Owned by ``_SCHEMA_POINTER`` in
#: ``tmx/tmx/tm_qa/detectors/e136_api_details_schema.py``; copied here only to
#: pin that the latest schema keeps it resolvable, since tmx does not ship
#: with this package. ``%5C`` is the URI-encoded backslash of the threat id
#: pattern.
E136_POINTER = (
    r"#/properties/threats/patternProperties/^[A-Za-z0-9]+%5C.T[0-9]+$"
    r"/properties/api_details"
)

#: One id per section, matching that section's ``patternProperties`` key.
IDS: dict[str, str] = {
    "feature_classes": "S3.FC1",
    "threats": "S3.T1",
    "control_objectives": "S3.CO1",
    "controls": "S3.C1",
    "actions": "S3.A1",
}

#: The ids given a stub in the stubbed document.
STUB_IDS: dict[str, str] = {
    "feature_classes": "S3.FC9",
    "threats": "S3.T9",
    "control_objectives": "S3.CO9",
    "controls": "S3.C9",
    "actions": "S3.A9",
}


def _live_document() -> dict[str, Any]:
    """A minimal document that satisfies every required field."""
    return {
        "metadata": {
            "provider": "aws",
            "service": "s3",
            "service_name": "S3",
            "version": "20260925",
            "scf_version": "2025.1",
            "license": "Proprietary",
        },
        "scorecard": {},
        "feature_classes": {
            "S3.FC1": {
                "name": "Bucket",
                "class_relationship": [],
                "description": "d",
                "long_description": "ld",
                "order": 1,
                "retired": False,
            }
        },
        "threats": {
            "S3.T1": {
                "feature_class": "S3.FC1",
                "name": "n",
                "description": "d",
                "access": {"UNIQUE": "s3:GetObject"},
                "api_details": {"UNIQUE": "GetObject"},
                "hlgoal": "Exfiltration",
                "mitre_attack": "TA0010",
                "cvss": "CVSS:3.1/AV:N",
                "retired": False,
                "cvss_severity": "Low",
                "cvss_score": 3.5,
            }
        },
        "control_objectives": {
            "S3.CO1": {"description": "d", "scf": ["IAC-01"], "retired": False}
        },
        "controls": {
            "S3.C1": {
                "coso": "Preventive",
                "nist_csf": "Protect",
                "objective": "S3.CO1",
                "retired": False,
                "description": "d",
                "testing": "t",
                "effort": "Low",
                "mitigate": [
                    {
                        "threat": "S3.T1",
                        "impact": "Low",
                        "priority": 1,
                        "max_dependency": 1,
                        "priority_overall": 1,
                        "cvss": "Low",
                    }
                ],
                "feature_class": ["S3.FC1"],
                "weighted_priority": "Low",
                "weighted_priority_score": 1,
                "queryable_objective_id": 1,
                "queryable_id": 1,
            }
        },
        "actions": {
            "S3.A1": {
                "action_description": "d",
                "api": "GetObject",
                "endpoint": "s3",
                "feature_class": "S3.FC1",
                "feature_class_action_type": "read",
                "iam_permission": "s3:GetObject",
                "event_name": "GetObject",
                "stage": "v1",
                "action_id_int": 1,
                "retired": False,
            }
        },
        "dfd": {"body": "PGRpYWdyYW0+"},
    }


def _stubbed_document() -> dict[str, Any]:
    """The live document plus one ``{"retired": true}`` stub per section."""
    document = _live_document()
    for section, stub_id in STUB_IDS.items():
        document[section][stub_id] = {"retired": True}
    return document


def _with_entity(section: str, entity: dict[str, Any]) -> dict[str, Any]:
    document = _live_document()
    document[section][IDS[section]] = entity
    return document


# ------------------------------------------------------------- selection


def test_the_20260925_schema_ships_with_the_package() -> None:
    # Arrange
    folder = files("tmxcaliber").joinpath("schema").joinpath("threatmodel")

    # Act
    names = {entry.name for entry in folder.iterdir()}

    # Assert
    assert {"20240423.json", "20260925.json"} <= names


def test_the_latest_schema_is_no_older_than_20260925() -> None:
    # Arrange / Act
    latest = schema_mod._select_latest_schema_resource("threatmodel")

    # Assert
    assert latest >= "20260925.json"


# ---------------------------------------------------------- valid documents


def test_a_live_document_validates() -> None:
    # Arrange
    document = _live_document()

    # Act / Assert: raises on failure
    validate_threatmodel_schema(document)


def test_a_document_with_a_stub_in_every_section_validates() -> None:
    # Arrange
    document = _stubbed_document()

    # Act / Assert: raises on failure
    validate_threatmodel_schema(document)


def test_a_full_record_marked_retired_validates() -> None:
    # Arrange: a retired control still referenced by a live one is exported as
    # a full record in non-stub outputs, so the live branch must accept it.
    live = _live_document()["controls"]["S3.C1"]
    document = _with_entity("controls", {**live, "retired": True})

    # Act / Assert: raises on failure
    validate_threatmodel_schema(document)


# -------------------------------------------------------- invalid documents


@pytest.mark.parametrize("section", RETIRABLE_SECTIONS)
def test_a_lone_false_flag_is_not_a_stub(section: str) -> None:
    # Arrange
    document = _with_entity(section, {"retired": False})

    # Act / Assert
    with pytest.raises(SchemaValidationError):
        validate_threatmodel_schema(document)


@pytest.mark.parametrize("section", RETIRABLE_SECTIONS)
def test_a_stub_with_any_other_field_is_rejected(section: str) -> None:
    # Arrange
    document = _with_entity(section, {"retired": True, "description": "d"})

    # Act / Assert
    with pytest.raises(SchemaValidationError):
        validate_threatmodel_schema(document)


@pytest.mark.parametrize("section", RETIRABLE_SECTIONS)
def test_a_live_entity_must_carry_the_flag(section: str) -> None:
    # Arrange
    entity = copy.deepcopy(_live_document()[section][IDS[section]])
    del entity["retired"]
    document = _with_entity(section, entity)

    # Act / Assert
    with pytest.raises(SchemaValidationError):
        validate_threatmodel_schema(document)


@pytest.mark.parametrize("section", RETIRABLE_SECTIONS)
def test_a_string_flag_is_rejected(section: str) -> None:
    # Arrange
    entity = {**_live_document()[section][IDS[section]], "retired": "false"}
    document = _with_entity(section, entity)

    # Act / Assert
    with pytest.raises(SchemaValidationError):
        validate_threatmodel_schema(document)


# ------------------------------------------------------------------- E136


def test_the_e136_pointer_accepts_valid_api_details() -> None:
    # Arrange
    api_details = {"OR": ["GetObject", {"api": "PutObject", "field": "Body"}]}

    # Act / Assert: raises on failure, including when the pointer is unresolvable
    validate_threatmodel_schema(instance=api_details, schema_pointer=E136_POINTER)


def test_the_e136_pointer_rejects_invalid_api_details() -> None:
    # Arrange
    api_details = {"UNKNOWN": "GetObject"}

    # Act / Assert
    with pytest.raises(SchemaValidationError):
        validate_threatmodel_schema(instance=api_details, schema_pointer=E136_POINTER)

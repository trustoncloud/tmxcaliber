from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path
from typing import Callable

import pytest

# Import the module to allow monkeypatching its "files" symbol
from tmxcaliber.schema import schema as schema_mod
from tmxcaliber.schema.schema import (
    SchemaValidationError,
    SchemaValidationUnavailable,
    validate_overwatch_schema,
    validate_threatmodel_schema,
)


@pytest.fixture()
def schema_env(tmp_path, monkeypatch) -> SimpleNamespace:
    """
    Prepare a temporary 'tmxcaliber/schema/{kind}' directory tree and
    monkeypatch schema.files() to return it, so the validator discovers
    JSON schemas from this temp location.
    """
    root = tmp_path / "pkgroot"
    tmxc = root / "tmxcaliber" / "schema"
    threats_dir = tmxc / "threatmodel"
    overwatch_dir = tmxc / "overwatch"
    threats_dir.mkdir(parents=True, exist_ok=True)
    overwatch_dir.mkdir(parents=True, exist_ok=True)

    def files_stub(pkg_name: str) -> Path:
        # Return the path pointing to our temporary package root
        return root / pkg_name

    monkeypatch.setattr(schema_mod, "files", files_stub, raising=True)

    def write_schema(kind: str, date: str, data: dict) -> Path:
        path = (tmxc / kind / f"{date}.json").resolve()
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    return SimpleNamespace(
        root=root,
        threats_dir=threats_dir,
        overwatch_dir=overwatch_dir,
        write=write_schema,
    )


def _has_ref_deps() -> bool:
    try:
        import referencing  # noqa: F401
        from jsonschema.validators import validator_for  # noqa: F401

        return True
    except Exception:
        return False


def _has_jsonschema() -> bool:
    try:
        import jsonschema  # noqa: F401

        return True
    except Exception:
        return False


@pytest.mark.skipif(not _has_jsonschema(), reason="jsonschema not installed")
def test_validate_threatmodel_schema_ok(schema_env: SimpleNamespace) -> None:
    # Minimal ThreatModel schema that requires a 'name' property
    schema_env.write(
        "threatmodel",
        "20240101",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.com/threatmodel.json",
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    )
    validate_threatmodel_schema({"name": "tmx"})


@pytest.mark.skipif(not _has_jsonschema(), reason="jsonschema not installed")
def test_validate_threatmodel_schema_error_details(schema_env: SimpleNamespace) -> None:
    # Schema enforcing 'name' to be present
    schema_env.write(
        "threatmodel",
        "20240102",
        {
            "$id": "https://example.com/threatmodel.json",
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    )
    with pytest.raises(SchemaValidationError) as ei:
        validate_threatmodel_schema({"not_name": "x"})
    err = ei.value
    assert err.validator == "required"
    # Message should mention the missing property
    assert (
        "required property" in err.message
        or "'name' is a required property" in err.message
    )
    # For a root-level required failure, paths may be empty (None)
    assert err.instance_pointer in (None, "#", "")
    assert err.schema_pointer is None or isinstance(err.schema_pointer, str)


@pytest.mark.skipif(not _has_jsonschema(), reason="jsonschema not installed")
def test_validate_overwatch_selects_latest(schema_env: SimpleNamespace) -> None:
    # Two versions; latest must be selected by date in filename
    schema_env.write(
        "overwatch",
        "20240101",
        {
            "type": "object",
            "properties": {"marker": {"const": "OLD"}},
            "required": ["marker"],
        },
    )
    schema_env.write(
        "overwatch",
        "20240202",
        {
            "type": "object",
            "properties": {"marker": {"const": "LATEST"}},
            "required": ["marker"],
        },
    )
    # Should pass with latest schema's const
    validate_overwatch_schema({"marker": "LATEST"})
    # Should fail when instance matches old const (not the latest)
    with pytest.raises(SchemaValidationError):
        validate_overwatch_schema({"marker": "OLD"})


@pytest.mark.skipif(not _has_jsonschema(), reason="jsonschema not installed")
def test_overwatch_no_schema_files_raises(
    schema_env: SimpleNamespace, monkeypatch
) -> None:
    # Point files() to an empty package root so no schemas are found
    empty_root = schema_env.root.parent / "empty"
    (empty_root / "tmxcaliber").mkdir(parents=True)
    monkeypatch.setattr(schema_mod, "files", lambda pkg: empty_root / pkg, raising=True)

    with pytest.raises(FileNotFoundError):
        validate_overwatch_schema({"anything": True})


@pytest.mark.skipif(not _has_jsonschema(), reason="jsonschema not installed")
def test_unavailable_jsonschema_bubbles(
    schema_env: SimpleNamespace, monkeypatch
) -> None:
    # Ensure there is at least one overwatch schema (won't be read because we short-circuit)
    schema_env.write(
        "overwatch",
        "20240101",
        {"type": "object", "properties": {}, "additionalProperties": True},
    )

    # Force the unavailability path
    def _raise_unavailable():
        raise SchemaValidationUnavailable("jsonschema missing")

    monkeypatch.setattr(
        schema_mod, "_ensure_jsonschema", _raise_unavailable, raising=True
    )

    with pytest.raises(SchemaValidationUnavailable):
        validate_overwatch_schema({"x": 1})


@pytest.mark.skipif(not _has_jsonschema(), reason="jsonschema not installed")
def test_subschema_validation_success_or_unavailable(
    schema_env: SimpleNamespace,
) -> None:
    # ThreatModel schema with nested array items, to test subschema validation
    schema_env.write(
        "threatmodel",
        "20240103",
        {
            "$id": "https://example.com/threatmodel.json",
            "type": "object",
            "properties": {
                "threats": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                        "required": ["id"],
                    },
                }
            },
            "required": ["threats"],
        },
    )
    instance = {"threats": [{"id": "T1"}]}

    if not _has_ref_deps():
        with pytest.raises(SchemaValidationUnavailable):
            validate_threatmodel_schema(
                instance,
                schema_pointer="#/properties/threats/items",
                instance_pointer="#/threats/0",
            )
        return

    # Should validate against the subschema pointed to by the $ref
    validate_threatmodel_schema(
        instance,
        schema_pointer="#/properties/threats/items",
        instance_pointer="#/threats/0",
    )

    # Now make it fail to exercise error pointers
    bad = {"threats": [{"not_id": "oops"}]}
    with pytest.raises(SchemaValidationError) as ei:
        validate_threatmodel_schema(
            bad,
            schema_pointer="#/properties/threats/items",
            instance_pointer="#/threats/0",
        )
    err = ei.value
    # Expect path pointing at the first element of threats
    assert err.instance_pointer is None or err.instance_pointer.endswith("/threats/0")
    assert err.validator == "required"


def test_SchemaValidationError_str_includes_details() -> None:
    err = SchemaValidationError(
        "boom",
        instance_pointer="#/a/0",
        schema_pointer="#/defs/X",
        validator="type",
        validator_value="object",
    )
    text = str(err)
    assert "boom" in text
    assert "#/a/0" in text
    assert "validator='type'" in text
    assert "validator_value='object'" in text

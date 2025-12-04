from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Iterable, Literal, Tuple

_SchemaKind = Literal["threatmodel", "overwatch"]


def _parse_compact_date_from_filename(name: str) -> int | None:
    """
    Extract a compact date in the form YYYYMMDD from the beginning of a filename.
    Returns the integer representation or None if not found/invalid.
    """
    m = re.match(r"^(\d{8})", name)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _iter_schema_candidates(kind: _SchemaKind) -> Iterable[Tuple[int, str]]:
    """
    Iterate over (yyyymmdd_as_int, resource_name) for JSON schema files in this package
    whose filename contains the kind substring and starts with YYYYMMDD.
    """
    pkg_root = files("tmxcaliber").joinpath("schema", kind)
    for entry in pkg_root.iterdir():
        name = entry.name
        if not name.lower().endswith(".json"):
            continue
        if kind not in name.lower():
            continue
        d = _parse_compact_date_from_filename(name)
        if d is None:
            continue
        yield d, name


def _select_latest_schema_resource(kind: _SchemaKind) -> str:
    """
    Select the latest JSON schema resource for the given kind,
    based strictly on the leading YYYYMMDD in the filename.
    """
    candidates = sorted(_iter_schema_candidates(kind), key=lambda t: t[0])
    if not candidates:
        raise FileNotFoundError(
            f"No JSON schema files found for '{kind}' in package '{__package__}'. "
            "Expected files named like 'YYYYMMDD-<kind>*.json'." # Note that the file name is only like YYYYMMDD.json AI!
        )
    return candidates[-1][1]


def _load_schema(kind: _SchemaKind) -> dict:
    resource_name = _select_latest_schema_resource(kind)
    with files("tmxcaliber").joinpath("schema", kind, resource_name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _ensure_jsonschema():
    try:
        import jsonschema
    except Exception as exc:
        raise RuntimeError(
            "jsonschema is required to validate data against the bundled JSON Schemas. "
            "Please install the 'jsonschema' package."
        ) from exc


def _validate(instance: object, kind: _SchemaKind) -> None:
    """
    Validate the given instance against the selected latest schema.
    Raises jsonschema.ValidationError on validation failure.
    """
    _ensure_jsonschema()
    import jsonschema

    schema = _load_schema(kind)
    jsonschema.validate(instance=instance, schema=schema)


def validate_threatmodel_schema(instance: object) -> None:
    """
    Validate instance against the latest ThreatModel schema (based on YYYYMMDD in filename).
    Raises jsonschema.ValidationError on validation failure.
    """
    _validate(instance, "threatmodel")


def validate_overwatch_schema(instance: object) -> None:
    """
    Validate instance against the latest Overwatch schema (based on YYYYMMDD in filename).
    Raises jsonschema.ValidationError on validation failure.
    """
    _validate(instance, "overwatch")

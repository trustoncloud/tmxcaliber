from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any, Iterable, Literal, Tuple

_SchemaKind = Literal["threatmodel", "overwatch"]

__all__ = ["validate_threatmodel_schema", "validate_overwatch_schema"]


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
    Iterate over (yyyymmdd_as_int, resource_name) for JSON schema files located under
    tmxcaliber/schema/{kind} whose filename starts with YYYYMMDD.
    """
    pkg_root = files("tmxcaliber").joinpath("schema", kind)
    for entry in pkg_root.iterdir():
        name = entry.name
        if not name.lower().endswith(".json"):
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
            f"No JSON schema files found for '{kind}' under 'tmxcaliber/schema/{kind}'. "
            "Expected files named like 'YYYYMMDD.json'."
        )
    return candidates[-1][1]


def _load_schema(kind: _SchemaKind) -> dict[str, Any]:
    resource_name = _select_latest_schema_resource(kind)
    with files("tmxcaliber").joinpath("schema", kind, resource_name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_json_pointer(doc: Any, pointer: str) -> Any:
    """
    Minimal JSON Pointer resolver supporting fragments beginning with '#/'.
    """
    if pointer in ("", "#"):
        return doc
    p = pointer[1:] if pointer.startswith("#") else pointer
    if not p.startswith("/"):
        raise ValueError(f"Invalid JSON Pointer: {pointer!r}")
    parts = p.lstrip("/").split("/")
    cur: Any = doc
    for raw in parts:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            idx = int(token)
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur[token]
        else:
            raise KeyError(f"Cannot resolve pointer segment {raw!r} in non-container")
    return cur


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


def validate_threatmodel_schema(
    instance: object,
    schema_pointer: str | None = None,
    instance_pointer: str | None = None,
) -> None:
    """
    Validate instance against the latest ThreatModel schema, or a subschema if schema_pointer is provided.

    Parameters:
    - instance: JSON-like object to validate.
    - schema_pointer: Optional JSON Pointer into the root schema (e.g. '#/$defs/Threat' or '#/properties/threats/items').
    - instance_pointer: Optional JSON Pointer into the instance (e.g. '#/threats/0').

    Raises:
    - jsonschema.ValidationError on validation failure.
    - KeyError/ValueError if the provided pointers cannot be resolved.
    """
    if not schema_pointer:
        _validate(instance, "threatmodel")
        return

    _ensure_jsonschema()
    import jsonschema

    root_schema = _load_schema("threatmodel")
    Validator = jsonschema.validators.validator_for(root_schema)
    Validator.check_schema(root_schema)

    target_instance = (
        _resolve_json_pointer(instance, instance_pointer) if instance_pointer else instance
    )

    resolver = jsonschema.RefResolver.from_schema(root_schema)  # deprecated but functional. Why that. AI?
    subschema = {"$ref": schema_pointer}
    validator = Validator(subschema, resolver=resolver)
    validator.validate(target_instance)


def validate_overwatch_schema(instance: object) -> None:
    """
    Validate instance against the latest Overwatch schema (based on YYYYMMDD in filename).
    Raises jsonschema.ValidationError on validation failure.
    """
    _validate(instance, "overwatch")

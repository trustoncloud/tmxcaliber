from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any, Iterable, Literal, Tuple

_SchemaKind = Literal["threatmodel", "overwatch"]

__all__ = [
    "validate_threatmodel_schema",
    "validate_overwatch_schema",
    "SchemaValidationError",
    "SchemaValidationUnavailable",
]


class SchemaValidationUnavailable(Exception):
    """
    Raised when schema validation cannot run because optional validation
    dependencies are not available in the runtime environment.
    """

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class SchemaValidationError(Exception):
    """
    Raised when schema validation fails. Carries rich context similar to
    jsonschema.ValidationError without exposing that dependency.
    """

    def __init__(
        self,
        message: str,
        *,
        instance_pointer: str | None = None,
        schema_pointer: str | None = None,
        validator: str | None = None,
        validator_value: Any | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.instance_pointer = instance_pointer
        self.schema_pointer = schema_pointer
        self.validator = validator
        self.validator_value = validator_value

    def __str__(self) -> str:
        base = self.message
        details = []
        if self.instance_pointer:
            details.append(f"instance at {self.instance_pointer}")
        if self.schema_pointer:
            details.append(f"schema at {self.schema_pointer}")
        if self.validator:
            details.append(f"validator={self.validator!r}")
        if self.validator_value is not None:
            details.append(f"validator_value={self.validator_value!r}")
        return f"{base} ({', '.join(details)})" if details else base


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


def _path_to_pointer(path_iterable) -> str | None:
    """
    Convert a jsonschema path iterable to a JSON Pointer string (e.g. "#/a/0/b").
    Returns None if the path is empty.
    """
    parts = list(path_iterable or [])
    if not parts:
        return None
    def esc(token: str) -> str:
        return token.replace("~", "~0").replace("/", "~1")
    segments = [esc(str(p)) for p in parts]
    return "#/" + "/".join(segments)


def _ensure_jsonschema():
    try:
        import jsonschema  # type: ignore
        return jsonschema
    except Exception as exc:
        raise SchemaValidationUnavailable(
            "Schema validation is unavailable because 'jsonschema' is not installed. "
            "Install it to enable validation."
        ) from exc


def _validate(instance: object, kind: _SchemaKind) -> None:
    """
    Validate the given instance against the selected latest schema.
    Raises SchemaValidationError on validation failure.
    """
    jsonschema = _ensure_jsonschema()
    schema = _load_schema(kind)
    try:
        jsonschema.validate(instance=instance, schema=schema)
    except jsonschema.ValidationError as e:
        # Build JSON Pointers for instance and schema paths
        instance_ptr = _path_to_pointer(getattr(e, "absolute_path", ()))
        schema_ptr = _path_to_pointer(getattr(e, "absolute_schema_path", ()))
        raise SchemaValidationError(
            e.message,
            instance_pointer=instance_ptr,
            schema_pointer=schema_ptr,
            validator=getattr(e, "validator", None),
            validator_value=getattr(e, "validator_value", None),
        ) from e


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
    - SchemaValidationError on validation failure.
    - SchemaValidationUnavailable if required validation dependencies are missing.
    - KeyError/ValueError if the provided pointers cannot be resolved.
    """
    if not schema_pointer:
        _validate(instance, "threatmodel")
        return

    jsonschema = _ensure_jsonschema()
    try:
        from referencing import Registry, Resource
        from jsonschema.validators import validator_for
    except Exception as exc:
        raise SchemaValidationUnavailable(
            "Subschema validation is unavailable because required dependencies "
            "('jsonschema' with 'referencing') are not installed."
        ) from exc

    root_schema = _load_schema("threatmodel")
    Validator = validator_for(root_schema)
    Validator.check_schema(root_schema)

    target_instance = (
        _resolve_json_pointer(instance, instance_pointer) if instance_pointer else instance
    )

    base_uri = root_schema.get("$id", f"urn:tmxcaliber:threatmodel:{_select_latest_schema_resource('threatmodel')}")  # Fallback URN used only for in-memory resolution
    registry = Registry().with_resources({base_uri: Resource.from_contents(root_schema)})

    subschema = {"$ref": f"{base_uri}{schema_pointer}"}
    validator = Validator(subschema, registry=registry)
    try:
        validator.validate(target_instance)
    except jsonschema.ValidationError as e:
        instance_ptr = _path_to_pointer(getattr(e, "absolute_path", ()))
        schema_ptr = _path_to_pointer(getattr(e, "absolute_schema_path", ()))
        raise SchemaValidationError(
            e.message,
            instance_pointer=instance_ptr,
            schema_pointer=schema_ptr,
            validator=getattr(e, "validator", None),
            validator_value=getattr(e, "validator_value", None),
        ) from e


def validate_overwatch_schema(instance: object) -> None:
    """
    Validate instance against the latest Overwatch schema (based on YYYYMMDD in filename).

    Raises:
    - SchemaValidationError on validation failure.
    - SchemaValidationUnavailable if required validation dependencies are missing.
    """
    _validate(instance, "overwatch")

from __future__ import annotations

import json
import re
from datetime import date, datetime
from importlib.resources import files
from typing import Iterable, Literal, Optional, Tuple, Union


_DateLike = Union[str, date, datetime]
_SchemaKind = Literal["threatmodel", "overwatch"]


def _parse_date_from_filename(name: str) -> Optional[date]:
    """
    Extract an ISO-like date from the beginning of a filename.

    Supports:
    - YYYY-MM-DD...
    - YYYYMMDD...

    Returns None if no leading date is found or parsing fails.
    """
    # Try YYYY-MM-DD
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", name)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            return None

    # Try YYYYMMDD
    m = re.match(r"^(\d{8})", name)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d").date()
        except ValueError:
            return None

    return None


def _to_date(value: _DateLike) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        # Accept both YYYY-MM-DD and YYYYMMDD
        value = value.strip()
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return datetime.strptime(value, "%Y%m%d").date()
    raise TypeError("Unsupported date type; expected str, date, or datetime.")


def _iter_schema_candidates(kind: _SchemaKind) -> Iterable[Tuple[date, str]]:
    """
    Iterate over (date, resource_name) for JSON schema files in this package
    whose filename contains the kind substring.
    """
    pkg_root = files(__package__)
    for entry in pkg_root.iterdir():
        name = entry.name
        if not name.lower().endswith(".json"):
            continue
        if kind not in name.lower():
            continue
        d = _parse_date_from_filename(name)
        if d is None:
            continue
        yield d, name


def _select_schema_resource(kind: _SchemaKind, when: Optional[_DateLike]) -> str:
    """
    Select the JSON schema resource name for the given kind and optional date.
    If when is None, choose the latest by date.
    """
    candidates = sorted(_iter_schema_candidates(kind), key=lambda t: t[0])
    if not candidates:
        raise FileNotFoundError(
            f"No JSON schema files found for '{kind}' in package '{__package__}'. "
            "Expected files named like 'YYYY-MM-DD-<kind>*.json' or 'YYYYMMDD-<kind>*.json'."
        )

    if when is None:
        return candidates[-1][1]

    target_date = _to_date(when)
    for d, name in candidates:
        if d == target_date:
            return name

    available = ", ".join(d.isoformat() for d, _ in candidates)
    raise FileNotFoundError(
        f"No schema for '{kind}' with date {target_date.isoformat()} found. "
        f"Available dates: {available}"
    )


def _load_schema(kind: _SchemaKind, when: Optional[_DateLike]) -> dict:
    resource_name = _select_schema_resource(kind, when)
    with files(__package__).joinpath(resource_name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _ensure_jsonschema():
    try:
        import jsonschema  # noqa: F401
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "jsonschema is required to validate data against the bundled JSON Schemas. "
            "Please install the 'jsonschema' package."
        ) from exc


def _validate(instance: object, kind: _SchemaKind, when: Optional[_DateLike]) -> None:
    """
    Validate the given instance against the selected schema.
    Raises jsonschema.ValidationError on validation failure.
    """
    _ensure_jsonschema()
    import jsonschema

    schema = _load_schema(kind, when)
    jsonschema.validate(instance=instance, schema=schema)


def validate_threatmodel_schema(instance: object, when: Optional[_DateLike] = None) -> None: # No, do not do "when" just use the schema date, which is a string YYYYMMDD only. Clean up the whole file. AI!
    """
    Validate instance against the latest (or specified date) ThreatModel schema.

    Parameters:
    - instance: The JSON-like object to validate.
    - when: Optional date selector (YYYY-MM-DD, YYYYMMDD, datetime, or date).
            If None, the latest dated schema is used.

    Raises:
    - RuntimeError if jsonschema is not installed.
    - FileNotFoundError if no appropriate schema file is found.
    - jsonschema.ValidationError if the instance is invalid.
    """
    _validate(instance, "threatmodel", when)


def validate_overwatch_schema(instance: object, when: Optional[_DateLike] = None) -> None:
    """
    Validate instance against the latest (or specified date) Overwatch schema.

    Parameters:
    - instance: The JSON-like object to validate.
    - when: Optional date selector (YYYY-MM-DD, YYYYMMDD, datetime, or date).
            If None, the latest dated schema is used.

    Raises:
    - RuntimeError if jsonschema is not installed.
    - FileNotFoundError if no appropriate schema file is found.
    - jsonschema.ValidationError if the instance is invalid.
    """
    _validate(instance, "overwatch", when)

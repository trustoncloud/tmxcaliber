"""Shared recursive JSON permission tree validator.

Used by E65-E72, E74, E130, E131 detectors. Each detector calls
:func:`validate_permissions` and filters results by its own rule ID.

The module also owns the two vocabulary helpers every permission-reading
rule needs: :func:`extract_leaf_permissions` (which leaves of an ``access``
tree count) and :func:`filter_generic` (which tokens are placeholders
rather than real permissions).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

#: Placeholder subpermission tokens that stand in for a not-yet-pinned
#: permission. Ordered, because :data:`_GENERIC` joins it into a regex
#: alternation embedded in every entry of :data:`PERMISSION_REGEX`.
GENERIC_SUBPERMISSIONS: tuple[str, ...] = (
    "depends",
    "deprecated",
    "any",
    "service",
    "-",
)

_GENERIC_SET = frozenset(GENERIC_SUBPERMISSIONS)
_GENERIC = "|".join(GENERIC_SUBPERMISSIONS)

PERMISSION_REGEX = {
    "aws": re.compile(
        rf"^([a-zA-Z0-9\-]+:([\w\-]+|{_GENERIC})"
        rf"|TransformWorkspace:[a-zA-Z]+)$"
        rf"|LocalAccess[a-zA-Z0-9\-]*"
    ),
    "gcp": re.compile(
        rf"^(\w+\.(\w+|{_GENERIC})(\.(\w+|{_GENERIC}))?|ProjectApiKey|role:\w+)$"
    ),
    "azure": re.compile(
        rf"^((?:\w+\.\w+|\{{\w+\}})"
        rf"(\/([a-zA-Z0-9_-]+\.?\w+?|{_GENERIC}))+|"
        rf"Role\:[a-zA-Z0-9 ]+$|"
        rf"VaultAccessPolicy\:[a-zA-Z0-9.]+$|"
        rf"API\:[a-zA-Z0-9_-]+\.?[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+|"
        rf"ApiKey/(?:adminKey|queryKey|secretKey)|BasicAuth|"
        rf"directory:[RWX]{{1,3}};file:[RWX]{{1,3}})$"
    ),
}


@dataclass
class PermViolation:
    rule_id: str
    threat_id: str
    detail: str


def extract_leaf_permissions(
    access: object, *, exclude_optional: bool = True
) -> list[str]:
    """Collect every leaf permission string from an access JSON tree.

    Args:
        access: A leaf string, or a dict/list node of the access JSON tree.
        exclude_optional: When True, skip any subtree under an ``OPTIONAL``
            key, matching the legacy ``_extract_leaf_values(...,
            exclude_optional=True)`` behaviour. An OPTIONAL permission may
            legitimately sit outside the threat's FC scope or carry a
            non-canonical token, so it must not produce a finding.

    Returns:
        The leaf permission strings reachable under the given options.
    """
    perms: list[str] = []
    if isinstance(access, str):
        perms.append(access)
    elif isinstance(access, dict):
        for key, value in access.items():
            if exclude_optional and key == "OPTIONAL":
                continue
            perms.extend(
                extract_leaf_permissions(value, exclude_optional=exclude_optional)
            )
    elif isinstance(access, list):
        for item in access:
            perms.extend(
                extract_leaf_permissions(item, exclude_optional=exclude_optional)
            )
    return perms


def is_generic_permission(provider: str, perm: str) -> bool:
    """Return whether ``perm``'s subpermission is a generic placeholder.

    A generic placeholder token (e.g. AWS ``service:any``) stands in for a
    not-yet-pinned permission, so it must never drive a finding: it cannot
    be mapped to an owning feature class, matched against the action list,
    or format-checked.

    The segment inspected depends on provider syntax — AWS
    ``service:SUBPERMISSION``, GCP ``service.RESOURCE.VERB`` (either of the
    two segments after the service), Azure ``provider/SUBPATH/...``.

    Args:
        provider: The TM provider (``aws`` / ``gcp`` / ``azure``).
        perm: A single leaf permission token from a threat's ``access`` JSON.

    Returns:
        ``True`` when the relevant segment is in
        :data:`GENERIC_SUBPERMISSIONS`. ``False`` for an unknown provider or
        a token lacking the provider's delimiter.

    Examples:
        >>> is_generic_permission("aws", "s3:any")
        True
        >>> is_generic_permission("aws", "s3:GetObject")
        False
        >>> is_generic_permission("gcp", "storage.buckets.depends")
        True
    """
    if provider == "aws":
        parts = perm.split(":")
        return len(parts) > 1 and parts[1] in _GENERIC_SET
    if provider == "gcp":
        return any(s in _GENERIC_SET for s in perm.split(".")[1:3])
    if provider == "azure":
        parts = perm.split("/")
        return len(parts) > 1 and parts[1] in _GENERIC_SET
    return False


def filter_generic(provider: str, perms: list[str]) -> list[str]:
    """Drop generic placeholder tokens from a permission list.

    Args:
        provider: The TM provider (``aws`` / ``gcp`` / ``azure``).
        perms: Leaf permission tokens, typically from
            :func:`extract_leaf_permissions`.

    Returns:
        The tokens that are not generic placeholders, in the original order.

    Examples:
        >>> filter_generic("aws", ["s3:GetObject", "s3:any", "s3:PutObject"])
        ['s3:GetObject', 's3:PutObject']
    """
    return [p for p in perms if not is_generic_permission(provider, p)]


_VALID_KEYS = frozenset({"AND", "OR", "UNIQUE", "OPTIONAL"})


def _is_permission_leaf(key: str | None, perm_regex: re.Pattern[str] | None) -> bool:
    """Return whether ``key`` is a valid ``{permission: ...}`` leaf token.

    An ``OPTIONAL`` may wrap a leaf permission expressed as a single-key
    dict (``{"s3:GetObject": ...}``). Such a key is not one of the DSL
    keywords yet is still well-formed, so it must not be flagged as a
    wrong OPTIONAL value type.

    Args:
        key: The single dict key found under an ``OPTIONAL`` node, or
            ``None`` when the dict is empty.
        perm_regex: The provider's compiled permission regex, or ``None``
            when the provider has no regex (then nothing qualifies).

    Returns:
        ``True`` when ``key`` is a non-empty string matching ``perm_regex``.
    """
    if not key or perm_regex is None:
        return False
    return bool(perm_regex.search(key))


def validate_permissions(
    threats: list[dict[str, Any]],
    provider: str = "aws",
) -> list[PermViolation]:
    perm_regex = PERMISSION_REGEX.get(provider)
    results: list[PermViolation] = []
    for threat in threats:
        if threat.get("retired") == "true":
            continue
        access_raw = threat.get("access")
        if not access_raw:
            continue
        if isinstance(access_raw, str):
            try:
                access = json.loads(access_raw)
            except (json.JSONDecodeError, ValueError):
                continue
        else:
            access = access_raw
        threat_id = threat.get("id", "")
        _walk(access, threat_id, parent_keys=[], results=results, perm_regex=perm_regex)
    return results


def _walk(
    node: object,
    threat_id: str,
    parent_keys: list[str],
    results: list[PermViolation],
    perm_regex: re.Pattern[str] | None,
) -> None:
    try:
        if isinstance(node, dict):
            if len(node) == 0 and not parent_keys:
                return
            if len(node) != 1:
                results.append(
                    PermViolation("E66", threat_id, "dict must have exactly one key")
                )
                return
            key, value = next(iter(node.items()))
            if key not in _VALID_KEYS:
                results.append(PermViolation("E67", threat_id, f"invalid key: {key}"))

            if parent_keys and parent_keys[-1] == "UNIQUE":
                results.append(
                    PermViolation("E68", threat_id, "UNIQUE cannot have dict value")
                )

            if key in ("AND", "OR"):
                if parent_keys and parent_keys[-1] == key:
                    results.append(
                        PermViolation("E74", threat_id, f"duplicate nested {key}")
                    )
                if not isinstance(value, list):
                    results.append(
                        PermViolation("E69", threat_id, f"{key} must have list value")
                    )
                else:
                    for item in value:
                        if not isinstance(item, (str, dict)):
                            results.append(
                                PermViolation(
                                    "E70",
                                    threat_id,
                                    f"{key} list item must be str or dict",
                                )
                            )
                        elif isinstance(item, dict) and key == "OR":
                            item_key = next(iter(item), None)
                            if item_key == "OPTIONAL":
                                results.append(
                                    PermViolation(
                                        "E131", threat_id, "OPTIONAL inside OR"
                                    )
                                )
                            else:
                                _walk(
                                    item,
                                    threat_id,
                                    [*parent_keys, key],
                                    results,
                                    perm_regex,
                                )
                        else:
                            _walk(
                                item,
                                threat_id,
                                [*parent_keys, key],
                                results,
                                perm_regex,
                            )
            elif key == "UNIQUE":
                if not isinstance(value, str):
                    if (
                        isinstance(value, list)
                        and len(value) == 1
                        and isinstance(value[0], str)
                    ):
                        pass  # E73 auto-fix handles this
                    else:
                        results.append(
                            PermViolation(
                                "E71", threat_id, "UNIQUE value must be string"
                            )
                        )
            elif key == "OPTIONAL":
                if isinstance(value, dict):
                    opt_key = next(iter(value), None)
                    if opt_key == "UNIQUE":
                        results.append(
                            PermViolation(
                                "E72", threat_id, "OPTIONAL cannot contain UNIQUE dict"
                            )
                        )
                    elif opt_key not in ("AND", "OR") and not _is_permission_leaf(
                        opt_key, perm_regex
                    ):
                        results.append(
                            PermViolation(
                                "E130", threat_id, "OPTIONAL value type wrong"
                            )
                        )
                elif not isinstance(value, str):
                    if isinstance(value, list):
                        if len(value) != 1:
                            results.append(
                                PermViolation(
                                    "E130",
                                    threat_id,
                                    "OPTIONAL list must have exactly 1 element",
                                )
                            )
                        elif not isinstance(value[0], (str, dict)):
                            results.append(
                                PermViolation(
                                    "E130",
                                    threat_id,
                                    "OPTIONAL list item must be str or dict",
                                )
                            )
                        elif isinstance(value[0], dict):
                            opt_item_key = next(iter(value[0]), None)
                            if opt_item_key == "UNIQUE":
                                results.append(
                                    PermViolation(
                                        "E72",
                                        threat_id,
                                        "OPTIONAL cannot contain UNIQUE dict",
                                    )
                                )
                            elif opt_item_key not in (
                                "AND",
                                "OR",
                            ) and not _is_permission_leaf(opt_item_key, perm_regex):
                                results.append(
                                    PermViolation(
                                        "E130", threat_id, "OPTIONAL value type wrong"
                                    )
                                )
                    else:
                        results.append(
                            PermViolation(
                                "E130", threat_id, "OPTIONAL value type wrong"
                            )
                        )

        elif not parent_keys:
            results.append(
                PermViolation("E65", threat_id, "top-level value must be dict")
            )
    except (IndexError, ValueError):
        results.append(
            PermViolation("E134", threat_id, "structural error in permission JSON")
        )

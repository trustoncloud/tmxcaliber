"""The one place that decides what changed between two ThreatModel exports.

Two differs used to answer that question. ``lib.change_log.generate_change_log``
decided what blocks an OverWatch publish, comparing a new export against the
JSON already committed in the customer's GitHub repo. ``tmx``'s
``get_change_log_between_two_tm`` decided what could be *filed*, landing in
``tm_qa.tm_field_diffs``, which is the catalog Tower offers. The publish gate
blocks on the first and demands evidence sourced from the second, so it only
works while one property holds:

    Every change the blocking side can report must be expressible as a field id
    the filing side can produce.

Nothing enforced that, and it broke four ways at once:

===========================  ===========================================
``control_objectives.*.scf`` set-diffed here, invisible there (a list, and
                             the filing differ never read DeepDiff's
                             ``iterable_item_*`` buckets)
``controls.*.mitigate``      diffed here, suppressed there
``dfd.body``                 raw inequality here, semantic there
``threats.*.access``         raw inequality here, normalized set there
===========================  ===========================================

The first two blocked publishes nobody could clear (the control ``owner``
column twice in August 2026, ``scf`` on 2026-08-27). The last two are the
mirror image: this side reported editor noise the other side correctly
suppressed, which blocks a publish just as hard.

This module is the fix. It produces one flat set of :class:`AtomicChange`, and
both consumers are pure projections of it (:func:`to_element_change_log` for
the customer-facing change log and the publish gate,
:func:`to_field_diff_rows` for the catalog). Neither re-diffs anything, so the
containment property above holds by construction rather than by vigilance.

The grain is the **field**, not the element, because a field-grain set folds up
to element grain and the reverse is impossible.

It lives in ``tmxcaliber`` rather than ``tmx`` because ``tmx`` depends on
``tmxcaliber`` and not the reverse, and because ``tmxcaliber``'s own CLI has a
``create_change_log`` operation that must not drift from what production runs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from deepdiff import DeepDiff

from tmxcaliber.lib.dfd_diff import DfdDecodeError, diff_dfd_bodies
from tmxcaliber.lib.permission_json import extract_leaf_permissions

JsonDict = dict[str, Any]

#: Categories whose items are keyed by element id and walked element by
#: element. Everything else in the document is diffed as a whole.
TOP_KEYS = [
    "controls",
    "threats",
    "control_objectives",
    "actions",
    "feature_classes",
    "scorecard",
]

#: Field ids suppressed for every consumer. Derived or bookkeeping values that
#: are regenerated on each export and are not a threat-model change.
#:
#: This replaces the two lists that used to disagree: ``CHANGES_TO_IGNORE`` on
#: the blocking side and ``_FIELD_DIFF_IGNORE`` on the filing side. Anything
#: here is invisible to BOTH, which is the point -- a value suppressed on one
#: side only is exactly how a publish blocks with nothing to file.
#:
#: Matched as a substring of the dotted field id, as both originals were.
IGNORED_FIELDS: tuple[str, ...] = (
    "metadata.service",
    "metadata.version",
    "metadata.release",
    "metadata.watermark",
    "metadata.provider",
    "metadata.timestamp",
    "weighted_priority_score",
    "weighted_priority",
    ".order",
    ".queryable_objective_id",
    ".score",
    ".cvss_score",
)


@dataclass(frozen=True)
class AtomicChange:
    """One change to one field of one element.

    Attributes:
        category: The owning category, e.g. ``controls`` or ``dfd``.
        identifier: The element id, e.g. ``S3.C1``. Empty for a change that
            belongs to the category itself rather than to an element.
        field: The changed field within the element, e.g. ``description`` or
            ``scf``. Empty when the whole element was added or removed.
        change_type: ``added``, ``removed`` or ``modified``.
        old_value: The previous value, or ``None`` for an addition.
        new_value: The current value, or ``None`` for a removal.
        additional_info: Headline context the renderers use (a threat's
            ``name`` and ``cvss_severity``, a control objective's
            ``description``, and so on).
        is_rollout: Whether this field is one the export introduced across a
            whole category, i.e. a schema change rather than content. See
            :func:`rolled_out_keys` and :func:`blocking_changes`.
    """

    category: str
    identifier: str
    field: str
    change_type: str
    old_value: Any = None
    new_value: Any = None
    additional_info: dict[str, Any] = dataclass_field(default_factory=dict)
    is_rollout: bool = False

    @property
    def element(self) -> str:
        """The element this change belongs to, as the publish gate names it."""
        return (
            f"{self.category}.{self.identifier}" if self.identifier else self.category
        )

    @property
    def field_id(self) -> str:
        """The dotted field id, as ``tm_qa.tm_field_diffs`` stores it."""
        return f"{self.element}.{self.field}" if self.field else self.element


def is_ignored(field_id: str) -> bool:
    """Whether this field id is suppressed for every consumer."""
    return any(ignored in field_id for ignored in IGNORED_FIELDS)


def field_id_from_path(path_list: list[Any]) -> str:
    """Build a canonical dotted field id from a DeepDiff path list.

    Dict keys join with ``.`` and integer list indices render as ``[i]``, so a
    path reads ``controls.S3.C1.mitigate[0].threat``. Kept identical to the
    scheme ``tm_qa.tm_field_diffs`` already stores, so existing captures keep
    matching.

    Args:
        path_list: A DeepDiff ``path(output_format="list")`` value.

    Returns:
        The canonical dotted field id.
    """
    parts: list[str] = []
    for element in path_list:
        if isinstance(element, int):
            parts.append(f"[{element}]")
        elif parts:
            parts.append(f".{element}")
        else:
            parts.append(str(element))
    return "".join(parts)


# --------------------------------------------------------------------------
# Normalized comparators
#
# Each answers one question -- "did this field really change?" -- for a field
# whose raw representation carries noise. There is exactly one answer per
# field, shared by every consumer. That is the whole point: before this, the
# blocking side and the filing side each had their own opinion, and a field
# where they disagreed produced an unclearable publish block.
# --------------------------------------------------------------------------

#: A comparator returns ``None`` when the field is unchanged, otherwise the
#: ``(old_value, new_value)`` pair to report.
Comparator = Callable[[Any, Any], "tuple[Any, Any] | None"]


def _scf_ids(value: Any) -> frozenset[str]:
    """The SCF control ids on a control objective, trimmed and de-duplicated."""
    if not isinstance(value, list):
        return frozenset()
    return frozenset(stripped for item in value if (stripped := str(item).strip()))


def compare_scf(old: Any, new: Any) -> tuple[Any, Any] | None:
    """Compare two SCF mapping lists as sets of ids.

    Order and duplicates are not a change. That is load-bearing rather than
    tidy: detector E166 is a stage-2 auto-fix that sorts and de-duplicates
    every ``scf`` cell on each QA run, so an order-sensitive comparison would
    report a change on every run of every ThreatModel.
    """
    old_ids, new_ids = _scf_ids(old), _scf_ids(new)
    if old_ids == new_ids:
        return None
    return ", ".join(sorted(old_ids)), ", ".join(sorted(new_ids))


def _leaf_permissions(value: Any) -> frozenset[str] | None:
    """A threat's flattened leaf permissions, or ``None`` if unparseable.

    An unparseable ``access`` cell yields ``None`` so the caller can skip the
    threat entirely rather than fabricate an add or a remove from a bad cell.
    The E6 gate is what surfaces the parse error.
    """
    import json

    if not value:
        return frozenset()
    try:
        access = json.loads(value) if isinstance(value, str) else value
    except (json.JSONDecodeError, ValueError):
        return None
    return frozenset(
        stripped
        for perm in extract_leaf_permissions(access, exclude_optional=False)
        if (stripped := perm.strip())
    )


def compare_access(old: Any, new: Any) -> tuple[Any, Any] | None:
    """Compare two threat ``access`` trees by their leaf permission sets.

    A reorder, an ``AND``/``OR`` reshape, or a whitespace-only edit (``eks:X ``
    to ``eks:X``) is not a change; only a genuine add, remove or rename is.
    """
    old_perms, new_perms = _leaf_permissions(old), _leaf_permissions(new)
    if old_perms is None or new_perms is None:
        return None
    if old_perms == new_perms:
        return None
    return ", ".join(sorted(old_perms)), ", ".join(sorted(new_perms))


def compare_dfd_body(old: Any, new: Any) -> tuple[Any, Any] | None:
    """Compare two drawio bodies by their actual cells.

    Ignores the volatile editor state a plain string comparison trips on: the
    ``<mxfile>`` ``etag`` and ``modified`` attributes and the ``dx``/``dy``
    viewport offset that drawio rewrites on every save. An undecodable body is
    treated as no change so a malformed diagram never fails a run.
    """
    try:
        dfd_diff = diff_dfd_bodies(old, new)
    except DfdDecodeError:
        return None
    if dfd_diff is None:
        return None
    return dfd_diff.summary_old(), dfd_diff.summary_new()


#: Comparators keyed by ``(category, field)``. A category of ``*`` applies the
#: comparator to that field name in every category.
COMPARATORS: dict[tuple[str, str], Comparator] = {
    ("control_objectives", "scf"): compare_scf,
    ("threats", "access"): compare_access,
    ("dfd", "body"): compare_dfd_body,
}


def comparator_for(category: str, field: str) -> Comparator | None:
    """The normalized comparator for a field, if it has one."""
    return COMPARATORS.get((category, field))


#: Derived properties inside a ``mitigate`` entry. Recomputed on every export
#: from the threat graph, so a change to one is not a threat-model change.
MITIGATE_DERIVED: tuple[str, ...] = ("priority_overall", "max_dependency", "priority")


def _mitigate_by_threat(value: Any) -> dict[str, JsonDict]:
    """A control's ``mitigate`` list keyed by threat, derived props dropped."""
    if not isinstance(value, list):
        return {}
    mapped: dict[str, JsonDict] = {}
    for entry in value:
        if not isinstance(entry, dict) or "threat" not in entry:
            continue
        mapped[str(entry["threat"])] = {
            key: val for key, val in entry.items() if key not in MITIGATE_DERIVED
        }
    return mapped


def compare_mitigate(old: Any, new: Any) -> tuple[Any, Any] | None:
    """Compare two ``mitigate`` lists keyed by threat.

    ``priority``, ``priority_overall`` and ``max_dependency`` are recomputed on
    every export, so a change confined to them is not reported. Order is not a
    change either, since the list is keyed before comparing.

    Reporting this at all is a deliberate reversal. ``mitigate`` used to be
    diffed by the blocking side and suppressed by the filing side, so a
    control-to-threat mapping change could block a publish with nothing to
    file. Suppressing it on both sides would have been the other way to make
    them agree, but it would have dropped a real change from the ThreatModel
    change log customers receive. Making it filable adds an affordance where
    there used to be a dead end, and adds no burden in practice: the publish
    gate already blocked on these.
    """
    old_map, new_map = _mitigate_by_threat(old), _mitigate_by_threat(new)
    if old_map == new_map:
        return None
    return ", ".join(sorted(old_map)), ", ".join(sorted(new_map))


COMPARATORS[("controls", "mitigate")] = compare_mitigate


def rolled_out_keys(items_old: JsonDict, items_new: JsonDict) -> set[str]:
    """Keys the new document introduced across a whole category.

    A key absent from **every** element on the old side and present on the new
    one is a change to the export schema, not to the threat model's content.
    Announcing it would report one code change as a change to every control of
    every ThreatModel, and the publish gate would then demand a TM Change Set
    per control for a rollout nobody can file: the filing side compares two
    documents produced by the same build, so a schema addition is identical on
    both sides and yields no row to click.

    That is exactly what the control ``owner`` column did on 2026-08-21.

    A key present on *some* old elements is a real change and is reported as
    one, so a genuine edit is never hidden by this. The rule is self-limiting
    per document: once a published JSON carries the key, the next comparison is
    an ordinary value diff. It stays permanently because a customer not
    delivered for months still holds the older shape.

    Unlike the original, this is applied **before** the per-field comparators
    rather than after, so a key introduced inside ``mitigate`` or ``scf`` is
    suppressed too. Those two used to read and consume their keys first and
    bypassed the rule entirely.

    Args:
        items_old: The category's elements in the previous document.
        items_new: The category's elements in the current document.

    Returns:
        Keys present in the new document's elements and in none of the old's.
    """
    old_keys: set[str] = set()
    for item in items_old.values():
        if isinstance(item, dict):
            old_keys |= set(item.keys())
    new_keys: set[str] = set()
    for item in items_new.values():
        if isinstance(item, dict):
            new_keys |= set(item.keys())
    return new_keys - old_keys


_MISSING = object()


def _values_differ(old: Any, new: Any) -> bool:
    """Whether two field values differ, ignoring container ordering."""
    if isinstance(old, (dict, list)) or isinstance(new, (dict, list)):
        return bool(DeepDiff(old, new, ignore_order=True, report_repetition=True))
    return bool(old != new)


def _element_changes(
    category: str,
    identifier: str,
    old_item: JsonDict,
    new_item: JsonDict,
    introduced: set[str],
) -> list[AtomicChange]:
    """Field-grain changes between two versions of one element."""
    changes: list[AtomicChange] = []
    for name in sorted(set(old_item) | set(new_item)):
        is_rollout = name in introduced
        old_value = old_item.get(name, _MISSING)
        new_value = new_item.get(name, _MISSING)
        field_id = f"{category}.{identifier}.{name}"
        if is_ignored(field_id):
            continue

        compare = comparator_for(category, name)
        if compare is not None:
            result = compare(
                None if old_value is _MISSING else old_value,
                None if new_value is _MISSING else new_value,
            )
            if result is None:
                continue
            changes.append(
                AtomicChange(
                    category=category,
                    identifier=identifier,
                    field=name,
                    change_type="modified",
                    old_value=result[0],
                    new_value=result[1],
                    is_rollout=is_rollout,
                )
            )
            continue

        if old_value is _MISSING:
            change_type, old_out, new_out = "added", None, new_value
        elif new_value is _MISSING:
            change_type, old_out, new_out = "removed", old_value, None
        elif _values_differ(old_value, new_value):
            change_type, old_out, new_out = "modified", old_value, new_value
        else:
            continue
        changes.append(
            AtomicChange(
                category=category,
                identifier=identifier,
                field=name,
                change_type=change_type,
                old_value=old_out,
                new_value=new_out,
                is_rollout=is_rollout,
            )
        )
    return changes


def diff_threatmodels(old_json: JsonDict, new_json: JsonDict) -> list[AtomicChange]:
    """Every change between two vanilla ThreatModel exports, at field grain.

    This is the single detection pass. Both the customer-facing change log and
    the TM QA field-diff catalog are projections of its output, so neither can
    see a change the other cannot.

    Args:
        old_json: The previous export (the "from" side).
        new_json: The current export (the "to" side).

    Returns:
        Every change, ordered deterministically by field id then change type,
        so the same pair of documents always yields the same list.
    """
    changes: list[AtomicChange] = []

    for category in TOP_KEYS:
        old_items = old_json.get(category, {}) or {}
        new_items = new_json.get(category, {}) or {}
        if not isinstance(old_items, dict) or not isinstance(new_items, dict):
            continue
        introduced = rolled_out_keys(old_items, new_items)

        for identifier in sorted(set(new_items) - set(old_items)):
            changes.append(
                AtomicChange(
                    category=category,
                    identifier=identifier,
                    field="",
                    change_type="added",
                    new_value=new_items[identifier],
                    additional_info={"element": new_items[identifier]},
                )
            )
        for identifier in sorted(set(old_items) - set(new_items)):
            changes.append(
                AtomicChange(
                    category=category,
                    identifier=identifier,
                    field="",
                    change_type="removed",
                    old_value=old_items[identifier],
                    additional_info={"element": old_items[identifier]},
                )
            )
        for identifier in sorted(set(old_items) & set(new_items)):
            old_item, new_item = old_items[identifier], new_items[identifier]
            if not isinstance(old_item, dict) or not isinstance(new_item, dict):
                continue
            changes.extend(
                _element_changes(category, identifier, old_item, new_item, introduced)
            )

    changes.extend(_category_changes(old_json, new_json))

    precedence = {"removed": 0, "added": 1, "modified": 2}
    return sorted(changes, key=lambda c: (c.field_id, precedence.get(c.change_type, 3)))


def _category_changes(old_json: JsonDict, new_json: JsonDict) -> list[AtomicChange]:
    """Changes outside the element-keyed categories: the DFD and metadata."""
    changes: list[AtomicChange] = []
    remaining = (set(old_json) | set(new_json)) - set(TOP_KEYS)

    for category in sorted(remaining):
        old_value = old_json.get(category, _MISSING)
        new_value = new_json.get(category, _MISSING)

        if category == "dfd":
            old_body = (old_json.get("dfd") or {}).get("body")
            new_body = (new_json.get("dfd") or {}).get("body")
            if old_value is _MISSING and new_value is not _MISSING:
                changes.append(AtomicChange("dfd", "", "body", "added", None, new_body))
                continue
            result = compare_dfd_body(old_body, new_body)
            if result is not None:
                changes.append(
                    AtomicChange("dfd", "", "body", "modified", result[0], result[1])
                )
            continue

        if not isinstance(old_value, dict) or not isinstance(new_value, dict):
            continue
        for name in sorted(set(old_value) | set(new_value)):
            field_id = f"{category}.{name}"
            if is_ignored(field_id):
                continue
            old_field = old_value.get(name, _MISSING)
            new_field = new_value.get(name, _MISSING)
            if old_field is _MISSING:
                changes.append(
                    AtomicChange(category, "", name, "added", None, new_field)
                )
            elif new_field is _MISSING:
                changes.append(
                    AtomicChange(category, "", name, "removed", old_field, None)
                )
            elif _values_differ(old_field, new_field):
                changes.append(
                    AtomicChange(category, "", name, "modified", old_field, new_field)
                )
    return changes


def blocking_changes(changes: list[AtomicChange]) -> list[AtomicChange]:
    """The subset a publish gate may block on.

    This is the **one** deliberate asymmetry between the two consumers, and it
    is deliberate in one direction only.

    A schema rollout (:func:`rolled_out_keys`) must not block: it is one code
    change presenting as a change to every element of every ThreatModel, and
    the analyst has nothing meaningful to say about it. But it must still be
    *filable*, so the catalog keeps it: on 2026-08-23 the control ``owner``
    rollout was deliberately filed as continuous improvement, and suppressing
    it on the filing side too would have removed that affordance.

    So the filing side is a superset of the blocking side, which is the safe
    direction: the containment property the publish gate depends on -- every
    blocking change is filable -- still holds. Suppressing on the filing side
    only is what breaks it, and that is the bug this module exists to prevent.

    Args:
        changes: The canonical set from :func:`diff_threatmodels`.

    Returns:
        The changes a gate may legitimately refuse a publish over.
    """
    return [change for change in changes if not change.is_rollout]

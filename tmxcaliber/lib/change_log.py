import json
from typing import Any

from .tm_diff import (
    AtomicChange,
    blocking_changes,
    diff_threatmodels,
)
from .tools import (
    convert_epoch_to_utc,
    extract_letters_and_number,
    sort_dict_list_by_id,
)

JsonDict = dict[str, Any]


class Change:
    def __init__(
        self,
        change_type: str,
        category: str | None = None,
        identifier: str | None = None,
    ) -> None:
        self.change_type = change_type
        self.category = category
        self.identifier = identifier
        self.sub_changes: list[Change] = []
        self.field_change: dict[str, Any] = {}
        self.additional_info: dict[str, Any] = {}

    def add_sub_change(self, change: "Change") -> None:
        self.sub_changes.append(change)

    def is_there_change(self) -> bool:
        return bool(self.sub_changes or self.field_change)

    def get_json(self) -> JsonDict:
        change_json: JsonDict = {"change_type": self.change_type}
        if self.category:
            change_json["category"] = self.category
        if self.identifier:
            change_json["identifier"] = self.identifier
        if self.sub_changes:
            change_json["changes"] = [
                subchange.get_json() for subchange in self.sub_changes
            ]
        if self.field_change:
            for key, value in self.field_change.items():
                change_json[key] = value
        if self.additional_info:
            change_json["additional_info"] = self.additional_info
        return change_json

    def get_short_md(self) -> str:
        short_mds: list[str] = []
        if not self.sub_changes:
            short_md = f"{self.change_type.capitalize()} {self.identifier}"
            if self.category == "feature_classes" and self.additional_info.get("name"):
                short_md += f" `{self.additional_info['name']}`"
            if self.category == "threats" and self.additional_info.get("cvss_severity"):
                short_md += f" ({self.additional_info['cvss_severity']})"
            if self.category == "controls" and self.additional_info.get(
                "weighted_priority"
            ):
                short_md += f" ({self.additional_info['weighted_priority']})"
            return short_md
        for change in self.sub_changes:
            short_md = (
                f"{self.change_type.capitalize()} {self.identifier}.{change.identifier}"
            )
            short_mds.append(short_md)
        return custom_md_join(short_mds)

    def get_long_md(self) -> str:
        if not self.sub_changes:
            if self.category == "threats" and self.additional_info.get("name"):
                return self.get_short_md() + f" `{self.additional_info['name']}`"
            if self.category == "control_objectives" and self.additional_info.get(
                "description"
            ):
                return self.get_short_md() + f" `{self.additional_info['description']}`"
            if self.category == "controls" and self.additional_info.get("description"):
                return self.get_short_md() + f" `{self.additional_info['description']}`"
            return self.get_short_md()
        long_md = ""
        for change in self.sub_changes:
            long_md = (
                f"{self.change_type.capitalize()} {self.identifier}.{change.identifier}"
            )
            if change.field_change.get("old_value") and change.field_change.get(
                "new_value"
            ):
                long_md += "\n```\n"
                long_md += f"From: {change.field_change['old_value']}\n"
                long_md += f"To:   {change.field_change['new_value']}\n"
                long_md += "```"
        return long_md


def custom_md_join(mds: list[str]) -> str:
    if not mds:
        return ""
    result = ["- " + mds[0]] if not mds[0].startswith("- ") else [mds[0]]
    for item in mds[1:]:
        if item.startswith("- "):
            result.append(item)
        else:
            result.append("- " + item)
    return "\n".join(result)


class ChangeLog:
    def __init__(self, old_epoch: int, new_epoch: int) -> None:
        self.changes: list[Change] = []
        self.old_epoch = old_epoch
        self.new_epoch = new_epoch

    def add_change(self, change: Change) -> None:
        if not isinstance(change, Change):
            raise ValueError("Only Changes object should be added in the ChangeLog")
        self.changes.append(change)

    def add_changes(self, changes: list[Change]) -> None:
        for change in changes:
            self.add_change(change)

    def empty(self) -> bool:
        return self.changes == []

    def get_sorted_changes(self) -> list[Change]:
        return sorted(
            self.changes,
            key=lambda change: (
                change.change_type,
                extract_letters_and_number(change.identifier or ""),
            ),
        )

    def get_json(self) -> JsonDict:
        return {
            "release": {
                "old_epoch": str(self.old_epoch),
                "old_utc": convert_epoch_to_utc(self.old_epoch),
                "new_epoch": str(self.new_epoch),
                "new_utc": convert_epoch_to_utc(self.new_epoch),
            },
            "change_log": sort_dict_list_by_id(
                [change.get_json() for change in self.changes], "identifier"
            ),
        }

    def get_md(self) -> str:
        md = "## Changes Summary\n\n"
        md += self.get_short_md() or "No changes."
        md += "\n\n## Changes\n\n"
        md += self.get_long_md() or "No changes."
        return md

    def get_short_md(self) -> str:
        return custom_md_join(
            [change.get_short_md() for change in self.get_sorted_changes()]
        )

    def get_long_md(self) -> str:
        return custom_md_join(
            [change.get_long_md() for change in self.get_sorted_changes()]
        )


def _added_element_info(category: str, element: JsonDict) -> dict[str, Any]:
    """Headline context the markdown renderer shows for a newly added element."""
    if category == "feature_classes":
        return {"name": element.get("name")}
    if category == "threats":
        return {
            "name": element.get("name"),
            "cvss_severity": element.get("cvss_severity"),
        }
    if category == "control_objectives":
        return {"description": element.get("description")}
    if category == "controls":
        return {
            "description": str(element.get("description", "")).replace('"', '\\"'),
            "weighted_priority": element.get("weighted_priority"),
        }
    return {}


def to_element_change_log(
    changes: list[AtomicChange], old_epoch: int, new_epoch: int
) -> ChangeLog:
    """Fold the canonical change set into the element-grain change log.

    A pure fold, never a second diff. This is the projection the customer-facing
    markdown change log and the OverWatch publish gate read: one entry per
    element, with one sub-change per changed field.

    Args:
        changes: The canonical set, already filtered by
            :func:`~tmxcaliber.lib.tm_diff.blocking_changes`.
        old_epoch: Release epoch of the previous export.
        new_epoch: Release epoch of the current export.

    Returns:
        The element-grain :class:`ChangeLog`.
    """
    change_log = ChangeLog(old_epoch, new_epoch)

    whole_element: dict[tuple[str, str], AtomicChange] = {}
    fields_by_element: dict[tuple[str, str], list[AtomicChange]] = {}
    order: list[tuple[str, str]] = []
    for change in changes:
        key = (change.category, change.identifier)
        if key not in fields_by_element:
            fields_by_element[key] = []
            order.append(key)
        if change.field == "":
            whole_element[key] = change
        else:
            fields_by_element[key].append(change)

    for key in order:
        category, identifier = key
        element_change = whole_element.get(key)
        if element_change is not None:
            entry = Change(
                change_type=element_change.change_type,
                category=category,
                identifier=identifier,
            )
            if element_change.change_type == "added":
                entry.additional_info = _added_element_info(
                    category, element_change.additional_info.get("element") or {}
                )
            change_log.add_change(entry)
            continue

        entry = Change(change_type="modified", category=category, identifier=identifier)
        for field_change in fields_by_element[key]:
            sub_change = Change(
                change_type=field_change.change_type,
                identifier=field_change.field,
            )
            sub_change.field_change = {
                "old_value": field_change.old_value,
                "new_value": field_change.new_value,
            }
            entry.add_sub_change(sub_change)
        if entry.is_there_change():
            change_log.add_change(entry)

    return change_log


def generate_change_log(old_json: JsonDict, new_json: JsonDict) -> ChangeLog:
    """Diff two ThreatModel exports into the element-grain change log.

    This is the **blocking** side of the OverWatch publish gate, and the source
    of the markdown change log attached to every ThreatModel delivery. It is a
    projection of :func:`~tmxcaliber.lib.tm_diff.diff_threatmodels`, the single
    canonical differ, and no longer walks the document itself.

    Sharing that differ with the filing side (``tm_qa.tm_field_diffs``, which is
    the catalog Tower offers) is the point. The two used to disagree in four
    places -- ``scf``, ``mitigate``, ``dfd.body`` and ``threats.*.access`` -- and
    every disagreement is a publish that blocks with nothing available to file.
    See :mod:`tmxcaliber.lib.tm_diff`.

    Args:
        old_json: The previously published export (the "from" side).
        new_json: The current export (the "to" side).

    Returns:
        The element-grain :class:`ChangeLog`.
    """
    old_json = json.loads(json.dumps(old_json))
    new_json = json.loads(json.dumps(new_json))
    return to_element_change_log(
        blocking_changes(diff_threatmodels(old_json, new_json)),
        int(old_json["metadata"]["release"]),
        int(new_json["metadata"]["release"]),
    )

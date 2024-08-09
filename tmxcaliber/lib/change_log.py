import json
from deepdiff import DeepDiff
from deepdiff.model import PrettyOrderedSet
from .tools import (
    convert_epoch_to_utc,
    sort_dict_list_by_id,
    extract_letters_and_number,
)
from typing import List

TOP_KEYS = [
    "controls",
    "threats",
    "control_objectives",
    "actions",
    "feature_classes",
    "scorecard",
]


class Change:
    def __init__(self, change_type, category=None, identifier=None):
        self.change_type = change_type
        self.category = category
        self.identifier = identifier
        self.sub_changes: List[Change] = []
        self.field_change = {}
        self.additional_info = {}

    def add_sub_change(self, Change):
        self.sub_changes.append(Change)

    def is_there_change(self):
        return self.sub_changes or self.field_change

    def get_json(self):
        change_json = {"change_type": self.change_type}
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

    def get_short_md(self):
        short_mds = []
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

    def get_long_md(self):
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


def custom_md_join(mds):
    if not mds:
        return ''
    if len(mds) > 0 and not mds[0].startswith("- "):
        result = ["- " + mds[0]]
    else:
        result = [mds[0]]
    for item in mds[1:]:
        if item.startswith("- "):
            result.append(item)
        else:
            result.append("- " + item)
    return "\n".join(result)


def safe_get(d, keys):
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key, {})
        else:
            return {}
    return d


def manual_diff(old_json, new_json) -> List[Change]:
    change_log = []

    for key in TOP_KEYS:
        items1 = old_json.get(key, {})
        items2 = new_json.get(key, {})

        # Manual diff for added and removed items at the identifier level
        added_items = set(items2.keys()) - set(items1.keys())
        removed_items = set(items1.keys()) - set(items2.keys())

        for item in added_items:
            change = Change(change_type="added", category=key, identifier=item)
            if key == "feature_classes":
                change.additional_info = {"name": items2[item]["name"]}
            if key == "threats":
                change.additional_info = {
                    "name": items2[item]["name"],
                    "cvss_severity": items2[item]["cvss_severity"],
                }
            elif key == "control_objectives":
                change.additional_info = {"description": items2[item]["description"]}
            elif key == "controls":
                change.additional_info = {
                    "description": items2[item]["description"].replace('"', '\\"'),
                    "weighted_priority": items2[item]["weighted_priority"],
                }
            change_log.append(change)

        for item in removed_items:
            change_log.append(
                Change(change_type="removed", category=key, identifier=item)
            )

    return change_log


class ChangeLog:

    def __init__(self, old_epoch: int, new_epoch: int):
        self.changes: List[Change] = []
        self.old_epoch = old_epoch
        self.new_epoch = new_epoch

    def add_change(self, change: Change):
        if not isinstance(change, Change):
            raise ValueError("Only Changes object should be added in the ChangeLog")
        self.changes.append(change)

    def add_changes(self, changes: List[Change]):
        for change in changes:
            self.add_change(change)

    def empty(self) -> bool:
        return self.changes == []

    def get_sorted_changes(self) -> List[Change]:
        return sorted(
            self.changes,
            key=lambda change: (
                change.change_type,
                extract_letters_and_number(change.identifier),
            ),
        )

    def get_json(self) -> dict:
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


def map_mitigate_by_threat(mitigate_list):
    return {mitigate["threat"]: mitigate for mitigate in mitigate_list}


def clean_diff_id(key):
    if isinstance(key, int):
        return key
    if "root['" in key:
        return key.replace("root['", "").replace("']", "")
    return key


CHANGES_TO_IGNORE = [
    "feature_classes.order",
    "threats.cvss_score",
    "controls.weighted_priority",
    "controls.weighted_priority_score",
    "controls.mitigate.priority_overall",
    "controls.mitigate.max_dependency",
    "controls.mitigate.priority",
    "scorecard.number_of_events.score",
    "scorecard.number_of_actions.score",
    "scorecard.event_coverage.score",
    "scorecard.api_without_event.score",
    "metadata.watermark",
    "metadata.release",
]


def get_changes_from_deepdiff(
    deepdiff, key=None, category=None, identifier=None
) -> List[Change]:
    changes = []
    for change_type, fields in deepdiff.items():
        if change_type in ["dictionary_item_added", "iterable_item_added"]:
            if isinstance(fields, dict):
                for field, value in fields.items():
                    changes.append(
                        Change(
                            change_type="added",
                            category=category,
                            identifier=clean_diff_id(field),
                        )
                    )
            if isinstance(fields, PrettyOrderedSet):
                for field in fields:
                    changes.append(
                        Change(
                            change_type="added",
                            category=category,
                            identifier=clean_diff_id(field),
                        )
                    )
        elif change_type in ["dictionary_item_removed", "iterable_item_removed"]:
            if isinstance(fields, dict):
                for field, value in fields.items():
                    changes.append(
                        Change(
                            change_type="removed",
                            category=category,
                            identifier=clean_diff_id(field),
                        )
                    )
            if isinstance(fields, PrettyOrderedSet):
                for field in fields:
                    changes.append(
                        Change(
                            change_type="removed",
                            category=category,
                            identifier=clean_diff_id(field),
                        )
                    )
        elif change_type in ["values_changed", "type_changes"]:
            for field, value in fields.items():
                if key and f"{key}.{clean_diff_id(field)}" in CHANGES_TO_IGNORE:
                    continue
                if (
                    key
                    and identifier
                    and f"{key}.{identifier}.{clean_diff_id(field)}"
                    in CHANGES_TO_IGNORE
                ):
                    continue
                change = Change(
                    change_type="modified",
                    category=category,
                    identifier=clean_diff_id(field),
                )
                change.field_change = {
                    "old_value": value.get("old_value"),
                    "new_value": value.get("new_value"),
                }
                changes.append(change)
    return changes


def diff_mitigate(mitigate1, mitigate2) -> List[Change]:
    changes = []

    # Find added and removed threats
    threats1 = set(mitigate1.keys())
    threats2 = set(mitigate2.keys())
    added_threats = threats2 - threats1
    removed_threats = threats1 - threats2

    for threat in added_threats:
        changes.append(Change(change_type="added", identifier=threat))

    for threat in removed_threats:
        changes.append(Change(change_type="removed", identifier=threat))

    # Find modified threats
    common_threats = threats1.intersection(threats2)
    for threat in common_threats:
        diff = DeepDiff(
            mitigate1[threat],
            mitigate2[threat],
            ignore_order=True,
            report_repetition=True,
        )
        if diff:
            change_logs = get_changes_from_deepdiff(diff, key="controls.mitigate")
            change = Change(change_type="modified", identifier=threat)
            for change_log in change_logs:
                change.add_sub_change(change_log)
            changes.append(change)

    return changes


def diff_scf(scf_list1, scf_list2) -> List[Change]:
    changes = []

    # Find added and removed scfs
    scfs1 = set(scf_list1)
    scfs2 = set(scf_list2)
    added_scfs = scfs2 - scfs1
    removed_scfs = scfs1 - scfs2

    for scf in added_scfs:
        changes.append(Change(change_type="added", identifier=scf))

    for scf in removed_scfs:
        changes.append(Change(change_type="removed", identifier=scf))
    return changes


def generate_change_log(old_json, new_json) -> ChangeLog:
    # Perform manual diff on top-level keys and identifiers
    old_json = json.loads(json.dumps(old_json))
    new_json = json.loads(json.dumps(new_json))

    change_log = ChangeLog(
        int(old_json["metadata"]["release"]), int(new_json["metadata"]["release"])
    )
    change_log.add_changes(manual_diff(old_json, new_json))

    # Identify remaining keys to perform deep diff
    remaining_keys = set(old_json.keys()).union(set(new_json.keys())) - set(TOP_KEYS)

    # Perform deep diff on remaining structure
    for key in remaining_keys:
        if key == "dfd":
            if key not in old_json and key in new_json:
                change_log.add_change(
                    Change("added", category="dfd", identifier="body")
                )
            elif (
                old_json.get("dfd")
                and new_json.get("dfd")
                and old_json["dfd"] != new_json["dfd"]
            ):
                change_log.add_change(
                    Change("modified", category="dfd", identifier="body")
                )
            continue
        if key in old_json and key in new_json:
            diff = DeepDiff(
                old_json[key], new_json[key], ignore_order=True, report_repetition=True
            )
            changes = get_changes_from_deepdiff(diff, key=key, category=key)
            change_log.add_changes(changes)

    # Perform diff on explored keys at the next level
    for key in TOP_KEYS:
        items1 = old_json.get(key, {})
        items2 = new_json.get(key, {})
        common_items = set(items1.keys()).intersection(set(items2.keys()))
        for item in common_items:
            item_change = Change(change_type="modified", category=key, identifier=item)
            item1 = items1[item]
            item2 = items2[item]

            if key == "controls":
                # Handle mitigate separately
                mitigate1 = map_mitigate_by_threat(item1.get("mitigate", []))
                mitigate2 = map_mitigate_by_threat(item2.get("mitigate", []))
                sub_mitigate_changes = diff_mitigate(mitigate1, mitigate2)
                if sub_mitigate_changes:
                    mitigate_change = Change(
                        change_type="modified", identifier="mitigate"
                    )
                    item_change.add_sub_change(mitigate_change)
                    for sub_mitigate_change in sub_mitigate_changes:
                        mitigate_change.add_sub_change(sub_mitigate_change)
                item1.pop("mitigate", None)
                item2.pop("mitigate", None)

            if key == "controls":
                # Remove feature_class as only informational based on the threats
                item1.pop("feature_class", None)
                item2.pop("feature_class", None)

            if key == "control_objectives":
                scf1 = item1.get("scf", [])
                scf2 = item2.get("scf", [])
                sub_scf_changes = diff_scf(scf1, scf2)
                if sub_scf_changes:
                    scf_change = Change(change_type="modified", identifier="scf")
                    item_change.add_sub_change(scf_change)
                    for sub_scf_change in sub_scf_changes:
                        scf_change.add_sub_change(sub_scf_change)
                item1.pop("scf", None)
                item2.pop("scf", None)

            if key == "threats" and "access" in item1 and "access" in item2:
                if item1["access"] != item2["access"]:
                    access_change = Change(change_type="modified", identifier="access")
                    access_change.field_change = {
                        "old_value": item1["access"],
                        "new_value": item2["access"],
                    }
                    item_change.add_sub_change(access_change)
                # Remove access from the items to perform deep diff on other fields
                item1.pop("access", None)
                item2.pop("access", None)

            diff = DeepDiff(item1, item2, ignore_order=True, report_repetition=True)
            if diff:
                sub_changes = get_changes_from_deepdiff(diff, key=key, identifier=item)
                for sub_change in sub_changes:
                    item_change.add_sub_change(sub_change)

            if item_change.is_there_change():
                change_log.add_change(item_change)

    return change_log

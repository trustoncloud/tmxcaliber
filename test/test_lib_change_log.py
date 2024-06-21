import pytest
from deepdiff import DeepDiff
from deepdiff.model import PrettyOrderedSet
from tmxcaliber.lib.change_log import (
    Change,
    ChangeLog,
    generate_change_log,
    manual_diff,
    get_changes_from_deepdiff,
)


@pytest.fixture
def sample_data():
    old_json = {
        "metadata": {"release": "1625155200"},  # Example epoch time
        "controls": {
            "Service.C1": {"description": "Old control 1", "weighted_priority": "High"},
            "Service.C2": {"description": "Old control 2", "weighted_priority": "High"},
        },
        "threats": {
            "Service.T1": {"name": "Old threat 1", "cvss_severity": "Low"},
            "Service.T2": {"name": "Old threat 2", "cvss_severity": "Medium"},
        },
    }

    new_json = {
        "metadata": {"release": "1627750800"},  # Example epoch time
        "controls": {
            "Service.C2": {"description": "Old control 2", "weighted_priority": "High"},
            "Service.C3": {"description": "New control 3", "weighted_priority": "Low"},
        },
        "threats": {
            "Service.T2": {"name": "Old threat 2", "cvss_severity": "High"},
            "Service.T3": {"name": "New threat 3", "cvss_severity": "Low"},
        },
    }

    return old_json, new_json


def test_change_initialization():
    change = Change(change_type="added", category="controls", identifier="Service.C1")
    assert change.change_type == "added"
    assert change.category == "controls"
    assert change.identifier == "Service.C1"
    assert change.sub_changes == []
    assert change.field_change == {}
    assert change.additional_info == {}


def test_add_sub_change():
    parent_change = Change(
        change_type="modified", category="controls", identifier="Service.C1"
    )
    sub_change = Change(
        change_type="added", category="controls", identifier="Service.C2"
    )
    parent_change.add_sub_change(sub_change)
    assert sub_change in parent_change.sub_changes


def test_is_there_change():
    change = Change(change_type="modified")
    assert not change.is_there_change()
    change.field_change = {"old_value": "old", "new_value": "new"}
    assert change.is_there_change()


def test_get_json():
    change = Change(change_type="added", category="controls", identifier="Service.C1")
    expected_json = {
        "change_type": "added",
        "category": "controls",
        "identifier": "Service.C1",
    }
    assert change.get_json() == expected_json


def test_generate_change_log(sample_data):
    old_json, new_json = sample_data
    change_log = generate_change_log(old_json, new_json)
    assert isinstance(change_log, ChangeLog)
    assert len(change_log.changes) > 0


def test_manual_diff(sample_data):
    old_json, new_json = sample_data
    changes = manual_diff(old_json, new_json)
    assert len(changes) == 4  # Added and removed items at identifier level


def test_get_changes_from_deepdiff():
    old_dict = {"a": 1, "b": 2}
    new_dict = {"a": 1, "b": 3, "c": 4}
    diff = DeepDiff(old_dict, new_dict, ignore_order=True)
    changes = get_changes_from_deepdiff(diff)
    assert len(changes) == 2  # One modified, one added


def test_changelog_add_change():
    changelog = ChangeLog(1625155200, 1627750800)
    change = Change(change_type="added", category="controls", identifier="Service.C1")
    changelog.add_change(change)
    assert change in changelog.changes


def test_changelog_get_sorted_changes():
    changelog = ChangeLog(1625155200, 1627750800)
    change1 = Change(change_type="added", category="controls", identifier="Service.C1")
    change2 = Change(
        change_type="removed", category="controls", identifier="Service.C2"
    )
    changelog.add_changes([change2, change1])
    sorted_changes = changelog.get_sorted_changes()
    assert sorted_changes == [change1, change2]


def test_changelog_get_json(sample_data):
    old_json, new_json = sample_data
    changelog = generate_change_log(old_json, new_json)
    changelog_json = changelog.get_json()
    assert "release" in changelog_json
    assert "change_log" in changelog_json


def test_changelog_get_md(sample_data):
    old_json, new_json = sample_data
    changelog = generate_change_log(old_json, new_json)
    md = changelog.get_md()
    assert "## Changes Summary" in md
    assert "## Changes" in md

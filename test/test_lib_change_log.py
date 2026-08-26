import pytest
from deepdiff import DeepDiff

from tmxcaliber.lib.change_log import (
    Change,
    ChangeLog,
    clean_diff_id,
    generate_change_log,
    get_changes_from_deepdiff,
    manual_diff,
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


def test_clean_diff_id():
    assert clean_diff_id("root['controls']['Service.C1']") == "controls.Service.C1"
    assert clean_diff_id("root['threats']['Service.T1']") == "threats.Service.T1"
    assert clean_diff_id("root['metadata']['release']") == "metadata.release"
    assert (
        clean_diff_id(
            "root['feature_classes']['Service.FC2']['class_relationship'][0]['class']"
        )
        == "feature_classes.Service.FC2.class_relationship[0].class"
    )
    assert clean_diff_id(123) == 123
    assert clean_diff_id("some_random_string") == "some_random_string"
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


def _tm(controls: dict, release: str) -> dict:
    """A minimal document carrying only the controls under test."""
    return {"metadata": {"release": release}, "controls": controls}


def _control_entries(log) -> list:
    """Every control entry the log produced, by identifier."""
    return [c.identifier for c in log.changes if c.category == "controls"]


def test_a_key_introduced_across_every_control_is_not_a_change():
    # The control `owner` column, exported for the first time on 2026-08-21. Every
    # published customer JSON predates it, so without this rule one code change reads
    # as a change to every control of every ThreatModel, and the OverWatch publish gate
    # demands a TM Change Set per control for a rollout nobody can file.
    old = _tm(
        {
            "Service.C1": {"description": "one"},
            "Service.C2": {"description": "two"},
        },
        "1625155200",
    )
    new = _tm(
        {
            "Service.C1": {"description": "one", "owner": "Customer"},
            "Service.C2": {"description": "two", "owner": "TrustOnCloud"},
        },
        "1627750800",
    )

    log = generate_change_log(old, new)

    assert _control_entries(log) == []


def test_a_real_change_to_that_field_is_still_reported():
    # The dangerous failure here is suppressing too much, so the other direction is
    # pinned as well: once the key exists on the old side it is ordinary content.
    old = _tm(
        {
            "Service.C1": {"description": "one", "owner": "Customer"},
            "Service.C2": {"description": "two", "owner": "Customer"},
        },
        "1625155200",
    )
    new = _tm(
        {
            "Service.C1": {"description": "one", "owner": "TrustOnCloud"},
            "Service.C2": {"description": "two", "owner": "Customer"},
        },
        "1627750800",
    )

    log = generate_change_log(old, new)

    assert _control_entries(log) == ["Service.C1"]


def test_a_key_only_some_controls_carry_is_a_change_not_a_rollout():
    # Present on some old items means the field is established, so adding it to another
    # control is a real edit. The rule is deliberately all-or-nothing.
    old = _tm(
        {
            "Service.C1": {"description": "one", "owner": "Customer"},
            "Service.C2": {"description": "two"},
        },
        "1625155200",
    )
    new = _tm(
        {
            "Service.C1": {"description": "one", "owner": "Customer"},
            "Service.C2": {"description": "two", "owner": "Customer"},
        },
        "1627750800",
    )

    log = generate_change_log(old, new)

    assert _control_entries(log) == ["Service.C2"]


def test_the_rollout_rule_does_not_hide_other_edits_on_the_same_control():
    # A control that changed for a real reason in the same release still reports, with
    # only the rolled-out key dropped from its diff.
    old = _tm({"Service.C1": {"description": "one"}}, "1625155200")
    new = _tm(
        {"Service.C1": {"description": "rewritten", "owner": "Customer"}},
        "1627750800",
    )

    log = generate_change_log(old, new)

    assert _control_entries(log) == ["Service.C1"]

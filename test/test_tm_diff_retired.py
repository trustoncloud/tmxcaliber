"""Tests for how the canonical differ reads the ``retired`` flag and stubs.

The OverWatch publish gate diffs a new export against the JSON already in the
customer's GitHub repo. There, threats, control objectives and controls hold
the Sheet text ``"false"``, and feature classes and actions have no
``retired`` key at all. A current export writes a JSON boolean on all five,
so a type-only difference must never read as a change, or every delivery
blocks with nothing to file. The released dataset also keeps retired ids as
``{"retired": true}`` stubs, which must read exactly like a dropped id.
"""

from typing import Any

import pytest

from tmxcaliber.lib.change_log import generate_change_log
from tmxcaliber.lib.tm_diff import (
    COMPARATORS,
    blocking_changes,
    compare_retired,
    diff_threatmodels,
)
from tmxcaliber.lib.tools import RETIRABLE_SECTIONS

STUB: dict[str, Any] = {"retired": True}


def _tm(release: str, **categories: Any) -> dict[str, Any]:
    tm: dict[str, Any] = {"metadata": {"release": release, "version": "20240423"}}
    tm.update(categories)
    return tm


def _field_ids(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    return [change.field_id for change in diff_threatmodels(old, new)]


def _threat(retired: object) -> dict[str, Any]:
    return {"name": "n", "cvss_severity": "Low", "retired": retired}


def _co(retired: object) -> dict[str, Any]:
    return {"description": "d", "scf": ["IAC-01"], "retired": retired}


def _control(retired: object) -> dict[str, Any]:
    return {"description": "d", "objective": "S.CO1", "retired": retired}


def _fc(**extra: Any) -> dict[str, Any]:
    return {"name": "fc", "class_relationship": [], **extra}


def _action(**extra: Any) -> dict[str, Any]:
    return {"api": "GetThing", "feature_class": "S.FC1", **extra}


# ---------------------------------------------------------- registration


def test_compare_retired_is_registered_for_every_retirable_section() -> None:
    # Arrange / Act
    registered = {
        section: COMPARATORS.get((section, "retired")) for section in RETIRABLE_SECTIONS
    }

    # Assert
    assert registered == {section: compare_retired for section in RETIRABLE_SECTIONS}


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("false", False),
        ("FALSE ", False),
        ("true", True),
        (None, False),
        (None, "false"),
        (False, False),
    ],
)
def test_compare_retired_ignores_type_only_differences(
    old: object, new: object
) -> None:
    # Arrange / Act
    result = compare_retired(old, new)

    # Assert
    assert result is None


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("false", True, ("false", "true")),
        (False, "true", ("false", "true")),
        (None, True, ("false", "true")),
        (True, False, ("true", "false")),
        ("true", None, ("true", "false")),
    ],
)
def test_compare_retired_reports_a_flip_as_lowercase_strings(
    old: object, new: object, expected: tuple[str, str]
) -> None:
    # Arrange / Act
    result = compare_retired(old, new)

    # Assert
    assert result == expected


# ------------------------------------------------------ string vs boolean


@pytest.mark.parametrize(
    ("category", "make"),
    [
        ("threats", _threat),
        ("control_objectives", _co),
        ("controls", _control),
    ],
)
def test_string_false_to_boolean_false_is_not_a_change(
    category: str, make: Any
) -> None:
    # Arrange: what a customer's GitHub repo holds against a current export.
    identifier = {"threats": "S.T1", "control_objectives": "S.CO1"}.get(
        category, "S.C1"
    )
    old = _tm("1", **{category: {identifier: make("false")}})
    new = _tm("2", **{category: {identifier: make(False)}})

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert changes == []


def test_a_leaked_retired_control_is_not_a_change_across_vintages() -> None:
    # Arrange: a retired control still referenced by a live one is exported
    # as a full record, "true" before the boolean change and true after.
    old = _tm("1", controls={"S.C1": _control("true")})
    new = _tm("2", controls={"S.C1": _control(True)})

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert changes == []


# ------------------------------------------- missing vs false (FCs, actions)


@pytest.mark.parametrize(
    ("category", "make"),
    [("feature_classes", _fc), ("actions", _action)],
)
def test_a_new_false_flag_on_every_element_is_neither_a_change_nor_a_rollout(
    category: str, make: Any
) -> None:
    # Arrange: the key is absent on every old element, so rolled_out_keys
    # names it; the comparator must still decide there is nothing to report,
    # otherwise the catalog would carry a rollout row for every element.
    prefix = "FC" if category == "feature_classes" else "A"
    old = _tm("1", **{category: {f"S.{prefix}1": make(), f"S.{prefix}2": make()}})
    new = _tm(
        "2",
        **{
            category: {
                f"S.{prefix}1": make(retired=False),
                f"S.{prefix}2": make(retired=False),
            }
        },
    )

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert changes == []


def test_a_new_false_flag_on_some_feature_classes_is_not_a_change() -> None:
    # Arrange: not a rollout (one old element already has the key), so only
    # the comparator stands between this and a reported change.
    old = _tm(
        "1",
        feature_classes={"S.FC1": _fc(retired=False), "S.FC2": _fc()},
    )
    new = _tm(
        "2",
        feature_classes={
            "S.FC1": _fc(retired=False),
            "S.FC2": _fc(retired=False),
        },
    )

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert changes == []


# -------------------------------------------------------------- real flips


def test_a_real_retirement_is_reported_with_lowercase_strings() -> None:
    # Arrange
    old = _tm("1", controls={"S.C1": _control("false")})
    new = _tm("2", controls={"S.C1": _control(True)})

    # Act
    changes = blocking_changes(diff_threatmodels(old, new))

    # Assert
    assert [(c.field_id, c.change_type, c.old_value, c.new_value) for c in changes] == [
        ("controls.S.C1.retired", "modified", "false", "true")
    ]


def test_a_real_flip_renders_in_the_change_log_as_before() -> None:
    # Arrange
    old = _tm("1625155200", threats={"S.T1": _threat(True)})
    new = _tm("1627750800", threats={"S.T1": _threat("false")})

    # Act
    markdown = generate_change_log(old, new).get_md()

    # Assert
    assert "Modified S.T1.retired" in markdown
    assert "From: true\nTo:   false" in markdown


# ------------------------------------------------------------------ stubs


@pytest.mark.parametrize("category", RETIRABLE_SECTIONS)
def test_a_live_entity_that_became_a_stub_is_removed(category: str) -> None:
    # Arrange
    old = _tm("1", **{category: {"S.X1": {"description": "d", "retired": False}}})
    new = _tm("2", **{category: {"S.X1": STUB}})

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert [(c.field_id, c.change_type) for c in changes] == [
        (f"{category}.S.X1", "removed")
    ]


def test_a_stub_reads_the_same_as_a_dropped_id() -> None:
    # Arrange
    old = _tm(
        "1",
        threats={"S.T1": _threat("false"), "S.T2": _threat("false")},
    )
    stubbed = _tm("2", threats={"S.T1": _threat(False), "S.T2": STUB})
    dropped = _tm("2", threats={"S.T1": _threat(False)})

    # Act
    from_stub = diff_threatmodels(old, stubbed)
    from_drop = diff_threatmodels(old, dropped)

    # Assert
    assert from_stub == from_drop
    assert [(c.field_id, c.change_type) for c in from_stub] == [
        ("threats.S.T2", "removed")
    ]


def test_a_stub_on_the_old_side_and_a_live_entity_on_the_new_is_added() -> None:
    # Arrange
    old = _tm("1", controls={"S.C1": STUB})
    new = _tm("2", controls={"S.C1": _control(False)})

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert [(c.field_id, c.change_type) for c in changes] == [
        ("controls.S.C1", "added")
    ]


@pytest.mark.parametrize(
    ("old_entry", "new_entry"),
    [(STUB, STUB), (None, STUB), (STUB, None)],
)
def test_a_stub_against_a_stub_or_an_absent_id_is_no_change(
    old_entry: dict[str, Any] | None, new_entry: dict[str, Any] | None
) -> None:
    # Arrange
    old_actions = {} if old_entry is None else {"S.A1": old_entry}
    new_actions = {} if new_entry is None else {"S.A1": new_entry}
    old = _tm("1", actions=old_actions)
    new = _tm("2", actions=new_actions)

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert changes == []


def test_stubs_do_not_count_toward_a_rollout() -> None:
    # Arrange: the same stub on both sides beside a live element that gains
    # the flag. Neither the stub nor the new key may surface as a change.
    old = _tm("1", feature_classes={"S.FC1": _fc(), "S.FC9": STUB})
    new = _tm("2", feature_classes={"S.FC1": _fc(retired=False), "S.FC9": STUB})

    # Act
    changes = diff_threatmodels(old, new)

    # Assert
    assert changes == []


def test_diffing_does_not_mutate_either_document() -> None:
    # Arrange
    old = _tm("1", controls={"S.C1": _control("false"), "S.C2": STUB})
    new = _tm("2", controls={"S.C1": _control(False), "S.C2": STUB})

    # Act
    diff_threatmodels(old, new)

    # Assert
    assert old["controls"] == {"S.C1": _control("false"), "S.C2": STUB}
    assert new["controls"] == {"S.C1": _control(False), "S.C2": STUB}


# ---------------------------------------------------------- change log


def test_the_change_log_is_empty_for_a_type_only_difference() -> None:
    # Arrange: every section in both vintages at once, the shape the publish
    # gate compares on the first delivery after the boolean change.
    old = _tm(
        "1625155200",
        feature_classes={"S.FC1": _fc()},
        threats={"S.T1": _threat("false")},
        control_objectives={"S.CO1": _co("false")},
        controls={"S.C1": _control("false")},
        actions={"S.A1": _action()},
    )
    new = _tm(
        "1627750800",
        feature_classes={"S.FC1": _fc(retired=False)},
        threats={"S.T1": _threat(False)},
        control_objectives={"S.CO1": _co(False)},
        controls={"S.C1": _control(False)},
        actions={"S.A1": _action(retired=False)},
    )

    # Act
    change_log = generate_change_log(old, new)

    # Assert
    assert change_log.empty()
    assert change_log.get_md() == (
        "## Changes Summary\n\nNo changes.\n\n## Changes\n\nNo changes."
    )

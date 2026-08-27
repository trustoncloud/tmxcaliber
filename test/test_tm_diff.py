"""Tests for the single canonical ThreatModel differ.

Each case here is a field where the two old differs disagreed, and every
disagreement was a publish that blocked with nothing available to file. The
four are ``control_objectives.*.scf``, ``controls.*.mitigate``, ``dfd.body``
and ``threats.*.access``; see :mod:`tmxcaliber.lib.tm_diff`.
"""

from typing import Any

from tmxcaliber.lib.tm_diff import blocking_changes, diff_threatmodels


def _tm(release: str, **categories: Any) -> dict[str, Any]:
    tm: dict[str, Any] = {"metadata": {"release": release, "version": "20240423"}}
    tm.update(categories)
    return tm


def _field_ids(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    return [change.field_id for change in diff_threatmodels(old, new)]


def _co(scf: list[str]) -> dict[str, Any]:
    return {"S.CO1": {"description": "one", "scf": scf}}


def _control(mitigate: list[dict[str, Any]]) -> dict[str, Any]:
    return {"S.C1": {"description": "d", "objective": "S.CO1", "mitigate": mitigate}}


def _threat(access: str) -> dict[str, Any]:
    return {"S.T1": {"name": "n", "cvss_severity": "Low", "access": access}}


# ----------------------------------------------------------------- scf


def test_an_added_scf_id_is_reported():
    # The 2026-08-27 azure-subscription block. A net add lands in DeepDiff's
    # iterable_item_added bucket, which the old filing differ never read, so
    # the catalog had no row and the gate could not be satisfied.
    old = _tm("1", control_objectives=_co(["IAC-01"]))
    new = _tm("2", control_objectives=_co(["IAC-01", "MON-02"]))

    assert _field_ids(old, new) == ["control_objectives.S.CO1.scf"]


def test_a_removed_scf_id_is_reported():
    old = _tm("1", control_objectives=_co(["IAC-01", "MON-02"]))
    new = _tm("2", control_objectives=_co(["IAC-01"]))

    assert _field_ids(old, new) == ["control_objectives.S.CO1.scf"]


def test_reordered_scf_ids_are_not_a_change():
    # Load-bearing: detector E166 is a stage-2 auto-fix that sorts and
    # de-duplicates every scf cell on each QA run. An order-sensitive
    # comparison would report a change on every run of every ThreatModel.
    old = _tm("1", control_objectives=_co(["MON-02", "IAC-01"]))
    new = _tm("2", control_objectives=_co(["IAC-01", "MON-02"]))

    assert _field_ids(old, new) == []


def test_duplicated_scf_ids_are_not_a_change():
    old = _tm("1", control_objectives=_co(["IAC-01", "IAC-01", "MON-02"]))
    new = _tm("2", control_objectives=_co(["IAC-01", "MON-02"]))

    assert _field_ids(old, new) == []


# ------------------------------------------------------------ mitigate


def test_a_new_threat_mapping_is_reported():
    # mitigate used to be diffed by the blocking side and suppressed by the
    # filing side (`.mitigate` was in tmx's _FIELD_DIFF_IGNORE), so a
    # control-to-threat mapping change blocked with nothing to file.
    old = _tm("1", controls=_control([{"threat": "S.T1"}]))
    new = _tm("2", controls=_control([{"threat": "S.T1"}, {"threat": "S.T2"}]))

    assert _field_ids(old, new) == ["controls.S.C1.mitigate"]


def test_a_change_confined_to_derived_mitigate_props_is_not_a_change():
    # priority / priority_overall / max_dependency are recomputed from the
    # threat graph on every export.
    old = _tm("1", controls=_control([{"threat": "S.T1", "priority": "high"}]))
    new = _tm(
        "2",
        controls=_control(
            [{"threat": "S.T1", "priority": "low", "max_dependency": "3"}]
        ),
    )

    assert _field_ids(old, new) == []


def test_reordered_mitigate_entries_are_not_a_change():
    old = _tm("1", controls=_control([{"threat": "S.T2"}, {"threat": "S.T1"}]))
    new = _tm("2", controls=_control([{"threat": "S.T1"}, {"threat": "S.T2"}]))

    assert _field_ids(old, new) == []


# -------------------------------------------------------------- access


def test_a_real_permission_change_is_reported():
    old = _tm("1", threats=_threat('{"OR": ["eks:X"]}'))
    new = _tm("2", threats=_threat('{"OR": ["eks:X", "eks:Z"]}'))

    assert _field_ids(old, new) == ["threats.S.T1.access"]


def test_a_reordered_or_whitespace_only_access_edit_is_not_a_change():
    # The blocking side used to compare the raw access string, so a cosmetic
    # edit blocked a publish while the catalog, which compares normalized leaf
    # permission sets, offered nothing to file against it.
    old = _tm("1", threats=_threat('{"OR": ["eks:X ", "eks:Y"]}'))
    new = _tm("2", threats=_threat('{"OR": ["eks:Y", "eks:X"]}'))

    assert _field_ids(old, new) == []


def test_an_unparseable_access_cell_never_fabricates_a_change():
    # The E6 gate surfaces the parse error; a bad cell must not invent a diff.
    old = _tm("1", threats=_threat('{"OR": ["eks:X"]}'))
    new = _tm("2", threats=_threat("{not json"))

    assert _field_ids(old, new) == []


# ----------------------------------------------------------- rollouts


def test_a_key_introduced_across_a_whole_category_does_not_block():
    # The control `owner` column, first exported 2026-08-21. One code change
    # must not read as a change to every control of every ThreatModel.
    old = _tm(
        "1", controls={"S.C1": {"description": "a"}, "S.C2": {"description": "b"}}
    )
    new = _tm(
        "2",
        controls={
            "S.C1": {"description": "a", "owner": "Security"},
            "S.C2": {"description": "b", "owner": "Platform"},
        },
    )

    assert blocking_changes(diff_threatmodels(old, new)) == []


def test_a_rollout_is_still_offered_for_filing():
    # The other half of the same rule, and the direction that is easy to get
    # wrong. The rollout must not BLOCK, but it must stay FILABLE: on
    # 2026-08-23 the owner rollout was deliberately filed as continuous
    # improvement. Suppressing it on the filing side too would break the
    # containment property the publish gate depends on.
    old = _tm(
        "1", controls={"S.C1": {"description": "a"}, "S.C2": {"description": "b"}}
    )
    new = _tm(
        "2",
        controls={
            "S.C1": {"description": "a", "owner": "Security"},
            "S.C2": {"description": "b", "owner": "Platform"},
        },
    )

    assert _field_ids(old, new) == ["controls.S.C1.owner", "controls.S.C2.owner"]


def test_a_key_introduced_inside_scf_does_not_block():
    # The bypass that used to leak: the old blocking differ applied its
    # rollout rule AFTER the mitigate and scf blocks had already read and
    # consumed their keys, so a rollout inside either one blocked anyway.
    old = _tm(
        "1",
        control_objectives={
            "S.CO1": {"description": "one"},
            "S.CO2": {"description": "two"},
        },
    )
    new = _tm(
        "2",
        control_objectives={
            "S.CO1": {"description": "one", "scf": ["IAC-01"]},
            "S.CO2": {"description": "two", "scf": ["MON-02"]},
        },
    )

    assert blocking_changes(diff_threatmodels(old, new)) == []


def test_a_key_only_some_elements_carry_is_a_real_change():
    old = _tm(
        "1",
        controls={
            "S.C1": {"description": "a", "owner": "Security"},
            "S.C2": {"description": "b"},
        },
    )
    new = _tm(
        "2",
        controls={
            "S.C1": {"description": "a", "owner": "Platform"},
            "S.C2": {"description": "b"},
        },
    )

    assert [c.field_id for c in blocking_changes(diff_threatmodels(old, new))] == [
        "controls.S.C1.owner"
    ]


# ------------------------------------------------------ determinism


def test_the_same_pair_always_yields_the_same_rows():
    old = _tm("1", control_objectives=_co(["MON-02", "IAC-01"]), controls=_control([]))
    new = _tm(
        "2", control_objectives=_co(["IAC-01"]), controls=_control([{"threat": "S.T1"}])
    )

    assert _field_ids(old, new) == _field_ids(old, new)
    assert _field_ids(old, new) == sorted(_field_ids(old, new))

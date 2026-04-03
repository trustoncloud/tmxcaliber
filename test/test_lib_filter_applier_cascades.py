import pytest

from tmxcaliber.lib.filter import Filter
from tmxcaliber.lib.filter_applier import FilterApplier
from tmxcaliber.lib.threatmodel_data import ThreatModelData


@pytest.fixture(scope="function")
def rich_tm() -> ThreatModelData:
    data = {
        "metadata": {"release": "1710000000", "name": "RichModel"},
        "feature_classes": {
            "Svc.FC1": {"class_relationship": []},
            "Svc.FC2": {"class_relationship": [{"type": "parent", "class": "Svc.FC1"}]},
            "Svc.FC3": {"class_relationship": []},
        },
        "threats": {
            "Svc.T1": {
                "feature_class": "Svc.FC2",
                "cvss_severity": "High",
                "name": "Threat1",
                "access": {"AND": ["perm.read"]},
            },
            "Svc.T2": {
                "feature_class": "Svc.FC3",
                "cvss_severity": "Low",
                "name": "Threat2",
                "access": {"AND": ["perm.write"]},
            },
        },
        "control_objectives": {
            "Svc.CO1": {"description": "CO1"},
            "Svc.CO2": {"description": "CO2"},
        },
        "controls": {
            "Svc.C1": {
                "feature_class": ["Svc.FC2", "Svc.FC3"],
                "objective": "Svc.CO1",
                "coso": "Prevent",
                "description": "C1",
                "weighted_priority": "High",
                "assured_by": "Svc.CA1",
                "mitigate": [{"threat": "Svc.T1"}, {"threat": "Svc.T2"}],
            },
            "Svc.C2": {
                "feature_class": ["Svc.FC3"],
                "objective": "Svc.CO2",
                "coso": "Prevent",
                "description": "C2",
                "weighted_priority": "Low",
                "assured_by": "",
                "mitigate": [{"threat": "Svc.T2"}],
            },
            "Svc.CA1": {
                "feature_class": ["Svc.FC2"],
                "objective": "Svc.CO1",
                "coso": "Assurance",
                "description": "Assurance",
                "weighted_priority": "Very Low",
                "assured_by": "",
                "mitigate": [],
            },
        },
        "actions": {
            "Svc.A1": {"feature_class": "Svc.FC2"},
            "Svc.A2": {"feature_class": "Svc.FC3"},
        },
    }
    return ThreatModelData(data, add_to_list=False)


def test_filter_by_severity_cascades_and_preserves_casing(rich_tm: ThreatModelData):
    FilterApplier(Filter(severity="high"), exclude_as_filter=False).apply_filter(
        rich_tm
    )

    assert list(rich_tm.threats.keys()) == ["Svc.T1"]

    assert "Svc.C2" not in rich_tm.controls
    assert "Svc.C1" in rich_tm.controls
    assert rich_tm.controls["Svc.C1"]["mitigate"] == [{"threat": "Svc.T1"}]

    # Assurance control is pulled by get_controls_for_current_threats() via assured_by
    assert "Svc.CA1" in rich_tm.controls

    assert list(rich_tm.control_objectives.keys()) == ["Svc.CO1"]

    assert list(rich_tm.actions.keys()) == ["Svc.A1", "Svc.A2"]


def test_filter_by_feature_class_include_keeps_ancestors_and_prunes_relationships(
    rich_tm: ThreatModelData,
):
    FilterApplier(Filter(ids="Svc.FC2"), exclude_as_filter=False).apply_filter(rich_tm)

    assert "Svc.FC1" in rich_tm.feature_classes
    assert "Svc.FC2" in rich_tm.feature_classes
    assert "Svc.FC3" not in rich_tm.feature_classes

    for fc_id, fc_data in rich_tm.feature_classes.items():
        for rel in fc_data.get("class_relationship", []):
            assert rel.get("class") in rich_tm.feature_classes, (fc_id, rel)

    assert list(rich_tm.threats.keys()) == ["Svc.T1"]

    assert "Svc.C1" in rich_tm.controls
    assert rich_tm.controls["Svc.C1"]["feature_class"] == ["Svc.FC2"]
    assert "Svc.C2" not in rich_tm.controls

    assert list(rich_tm.actions.keys()) == ["Svc.A1"]


def test_filter_by_permissions_include(rich_tm: ThreatModelData):
    FilterApplier(
        Filter(permissions="perm.read"), exclude_as_filter=False
    ).apply_filter(rich_tm)

    assert list(rich_tm.threats.keys()) == ["Svc.T1"]
    assert "Svc.C2" not in rich_tm.controls
    assert "Svc.CO2" not in rich_tm.control_objectives
    assert list(rich_tm.actions.keys()) == ["Svc.A1", "Svc.A2"]


def test_filter_by_permissions_exclude(rich_tm: ThreatModelData):
    FilterApplier(Filter(permissions="perm.read"), exclude_as_filter=True).apply_filter(
        rich_tm
    )

    # Excluding permissions filters threats. Controls are then kept/removed based on
    # whether they still mitigate the remaining threats.
    assert list(rich_tm.threats.keys()) == ["Svc.T2"]

    # C1 still mitigates T2, so it remains, but is pruned to only the remaining threat.
    assert "Svc.C1" in rich_tm.controls
    assert rich_tm.controls["Svc.C1"]["mitigate"] == [{"threat": "Svc.T2"}]

    # Assurance control is pulled by get_controls_for_current_threats() via assured_by
    assert "Svc.CA1" in rich_tm.controls

    assert "Svc.CO1" in rich_tm.control_objectives
    assert "Svc.CO2" in rich_tm.control_objectives

    assert list(rich_tm.actions.keys()) == ["Svc.A1", "Svc.A2"]

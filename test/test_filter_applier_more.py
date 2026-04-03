from copy import deepcopy

from tmxcaliber.lib.filter import Filter
from tmxcaliber.lib.filter_applier import FilterApplier
from tmxcaliber.lib.threatmodel_data import ThreatModelData


def build_threatmodel(
    *,
    feature_classes=None,
    threats=None,
    controls=None,
    control_objectives=None,
    actions=None,
):
    return ThreatModelData(
        {
            "metadata": {"name": "Model", "release": "1710000000"},
            "feature_classes": deepcopy(
                feature_classes or {"Svc.FC1": {"class_relationship": []}}
            ),
            "threats": deepcopy(threats or {}),
            "controls": deepcopy(controls or {}),
            "control_objectives": deepcopy(control_objectives or {}),
            "actions": deepcopy(actions or {"Svc.A1": {"feature_class": "Svc.FC1"}}),
        },
        add_to_list=False,
    )


def test_filter_by_severity_supports_include_and_exclude():
    controls = {
        "Svc.C1": {
            "objective": "Svc.CO1",
            "coso": "Preventive",
            "feature_class": ["Svc.FC1"],
            "mitigate": [{"threat": "Svc.T1"}],
            "assured_by": "Svc.C3",
        },
        "Svc.C2": {
            "objective": "Svc.CO2",
            "coso": "Preventive",
            "feature_class": ["Svc.FC1"],
            "mitigate": [{"threat": "Svc.T2"}],
            "assured_by": "",
        },
        "Svc.C3": {
            "objective": "Svc.CO3",
            "coso": "Assurance",
            "feature_class": ["Svc.FC1"],
            "mitigate": [],
        },
    }
    objectives = {"Svc.CO1": {}, "Svc.CO2": {}, "Svc.CO3": {}}
    threats = {
        "Svc.T1": {"feature_class": "Svc.FC1", "cvss_severity": "High"},
        "Svc.T2": {"feature_class": "Svc.FC1", "cvss_severity": "Low"},
    }

    include_model = build_threatmodel(
        threats=threats,
        controls=controls,
        control_objectives=objectives,
    )
    FilterApplier(Filter(severity="high"), exclude_as_filter=False).apply_filter(
        include_model
    )
    assert list(include_model.threats.keys()) == ["Svc.T1"]
    assert list(include_model.controls.keys()) == ["Svc.C1", "Svc.C3"]
    assert list(include_model.control_objectives.keys()) == ["Svc.CO1", "Svc.CO3"]

    exclude_model = build_threatmodel(
        threats=threats,
        controls=controls,
        control_objectives=objectives,
    )
    FilterApplier(Filter(severity="high"), exclude_as_filter=True).apply_filter(
        exclude_model
    )
    assert list(exclude_model.threats.keys()) == ["Svc.T2"]
    assert list(exclude_model.controls.keys()) == ["Svc.C2"]
    assert list(exclude_model.control_objectives.keys()) == ["Svc.CO2"]


def test_filter_by_threats_supports_include_and_exclude():
    model = build_threatmodel(
        threats={
            "Svc.T1": {"feature_class": "Svc.FC1"},
            "Svc.T2": {"feature_class": "Svc.FC1"},
        },
        controls={
            "Svc.C1": {
                "objective": "Svc.CO1",
                "coso": "Preventive",
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T1"}],
                "assured_by": "Svc.C3",
            },
            "Svc.C2": {
                "objective": "Svc.CO2",
                "coso": "Preventive",
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T2"}],
                "assured_by": "",
            },
            "Svc.C3": {
                "objective": "Svc.CO3",
                "coso": "Assurance",
                "feature_class": ["Svc.FC1"],
                "mitigate": [],
            },
        },
        control_objectives={"Svc.CO1": {}, "Svc.CO2": {}, "Svc.CO3": {}},
    )

    FilterApplier(Filter(ids="Svc.T1"), exclude_as_filter=False).apply_filter(model)
    assert list(model.threats.keys()) == ["Svc.T1"]
    assert list(model.controls.keys()) == ["Svc.C1", "Svc.C3"]
    assert list(model.control_objectives.keys()) == ["Svc.CO1", "Svc.CO3"]

    model = build_threatmodel(
        threats={
            "Svc.T1": {"feature_class": "Svc.FC1"},
            "Svc.T2": {"feature_class": "Svc.FC1"},
        },
        controls={
            "Svc.C1": {
                "objective": "Svc.CO1",
                "coso": "Preventive",
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T1"}],
                "assured_by": "Svc.C3",
            },
            "Svc.C2": {
                "objective": "Svc.CO2",
                "coso": "Preventive",
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T2"}],
                "assured_by": "",
            },
            "Svc.C3": {
                "objective": "Svc.CO3",
                "coso": "Assurance",
                "feature_class": ["Svc.FC1"],
                "mitigate": [],
            },
        },
        control_objectives={"Svc.CO1": {}, "Svc.CO2": {}, "Svc.CO3": {}},
    )
    FilterApplier(Filter(ids="Svc.T1"), exclude_as_filter=True).apply_filter(model)
    assert list(model.threats.keys()) == ["Svc.T2"]
    assert list(model.controls.keys()) == ["Svc.C2"]
    assert list(model.control_objectives.keys()) == ["Svc.CO2"]


def test_filter_by_permissions_ignores_optional_permissions():
    threats = {
        "Svc.T1": {
            "feature_class": "Svc.FC1",
            "access": {"AND": ["perm.read"]},
        },
        "Svc.T2": {
            "feature_class": "Svc.FC1",
            "access": {"OPTIONAL": ["perm.read"]},
        },
    }
    controls = {
        "Svc.C1": {
            "objective": "Svc.CO1",
            "coso": "Preventive",
            "feature_class": ["Svc.FC1"],
            "mitigate": [{"threat": "Svc.T1"}],
            "assured_by": "Svc.C3",
        },
        "Svc.C2": {
            "objective": "Svc.CO2",
            "coso": "Preventive",
            "feature_class": ["Svc.FC1"],
            "mitigate": [{"threat": "Svc.T2"}],
            "assured_by": "",
        },
        "Svc.C3": {
            "objective": "Svc.CO3",
            "coso": "Assurance",
            "feature_class": ["Svc.FC1"],
            "mitigate": [],
        },
    }
    objectives = {"Svc.CO1": {}, "Svc.CO2": {}, "Svc.CO3": {}}

    include_model = build_threatmodel(
        threats=threats,
        controls=controls,
        control_objectives=objectives,
    )
    FilterApplier(
        Filter(permissions="perm.read"), exclude_as_filter=False
    ).apply_filter(include_model)
    assert list(include_model.threats.keys()) == ["Svc.T1"]
    assert list(include_model.controls.keys()) == ["Svc.C1", "Svc.C3"]

    exclude_model = build_threatmodel(
        threats=threats,
        controls=controls,
        control_objectives=objectives,
    )
    FilterApplier(Filter(permissions="perm.read"), exclude_as_filter=True).apply_filter(
        exclude_model
    )
    assert list(exclude_model.threats.keys()) == ["Svc.T2"]
    assert list(exclude_model.controls.keys()) == ["Svc.C2"]


def test_filter_by_controls_handles_upstream_and_downstream_dependencies():
    model = build_threatmodel(
        feature_classes={"svc.fc1": {"class_relationship": []}},
        threats={"svc.t1": {"feature_class": "svc.fc1"}},
        controls={
            "svc.c1": {
                "objective": "svc.co1",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "svc.c3",
            },
            "svc.c2": {
                "objective": "svc.co2",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "depends_on": "svc.c1",
                "assured_by": "",
            },
            "svc.c3": {
                "objective": "svc.co3",
                "coso": "Assurance",
                "feature_class": ["svc.fc1"],
                "mitigate": [],
            },
            "svc.c4": {
                "objective": "svc.co4",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "",
            },
        },
        control_objectives={
            "svc.co1": {},
            "svc.co2": {},
            "svc.co3": {},
            "svc.co4": {},
        },
    )

    FilterApplier(Filter(ids="svc.c2"), exclude_as_filter=False).apply_filter(model)
    assert list(model.controls.keys()) == ["svc.c1", "svc.c2"]
    assert list(model.control_objectives.keys()) == ["svc.co1", "svc.co2"]

    model = build_threatmodel(
        feature_classes={"svc.fc1": {"class_relationship": []}},
        threats={"svc.t1": {"feature_class": "svc.fc1"}},
        controls={
            "svc.c1": {
                "objective": "svc.co1",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "svc.c3",
            },
            "svc.c2": {
                "objective": "svc.co2",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "depends_on": "svc.c1",
                "assured_by": "",
            },
            "svc.c3": {
                "objective": "svc.co3",
                "coso": "Assurance",
                "feature_class": ["svc.fc1"],
                "mitigate": [],
            },
            "svc.c4": {
                "objective": "svc.co4",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "",
            },
        },
        control_objectives={
            "svc.co1": {},
            "svc.co2": {},
            "svc.co3": {},
            "svc.co4": {},
        },
    )
    FilterApplier(Filter(ids="svc.c1"), exclude_as_filter=True).apply_filter(model)
    assert list(model.controls.keys()) == ["svc.c4"]
    assert list(model.control_objectives.keys()) == ["svc.co4"]


def test_filter_by_control_objectives_supports_include_and_exclude():
    include_model = build_threatmodel(
        feature_classes={"svc.fc1": {"class_relationship": []}},
        threats={"svc.t1": {"feature_class": "svc.fc1"}},
        controls={
            "svc.c1": {
                "objective": "svc.co1",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "svc.c3",
            },
            "svc.c2": {
                "objective": "svc.co2",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "",
            },
            "svc.c3": {
                "objective": "svc.co3",
                "coso": "Assurance",
                "feature_class": ["svc.fc1"],
                "mitigate": [],
            },
        },
        control_objectives={"svc.co1": {}, "svc.co2": {}, "svc.co3": {}},
    )
    FilterApplier(Filter(ids="svc.co1"), exclude_as_filter=False).apply_filter(
        include_model
    )
    assert list(include_model.controls.keys()) == ["svc.c1"]
    assert list(include_model.control_objectives.keys()) == ["svc.co1"]

    exclude_model = build_threatmodel(
        feature_classes={"svc.fc1": {"class_relationship": []}},
        threats={"svc.t1": {"feature_class": "svc.fc1"}},
        controls={
            "svc.c1": {
                "objective": "svc.co1",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "svc.c3",
            },
            "svc.c2": {
                "objective": "svc.co2",
                "coso": "Preventive",
                "feature_class": ["svc.fc1"],
                "mitigate": [{"threat": "svc.t1"}],
                "assured_by": "",
            },
            "svc.c3": {
                "objective": "svc.co3",
                "coso": "Assurance",
                "feature_class": ["svc.fc1"],
                "mitigate": [],
            },
        },
        control_objectives={"svc.co1": {}, "svc.co2": {}, "svc.co3": {}},
    )
    FilterApplier(Filter(ids="svc.co1"), exclude_as_filter=True).apply_filter(
        exclude_model
    )
    assert list(exclude_model.controls.keys()) == ["svc.c2"]
    assert list(exclude_model.control_objectives.keys()) == ["svc.co2"]

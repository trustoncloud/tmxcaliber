from tmxcaliber.lib.threatmodel_data import ThreatModelData, get_permissions


def create_threatmodel(feature_classes=None, threats=None, controls=None):
    base_json = {"metadata": {"name": "Model"}, "control_objectives": {}, "actions": {}}
    base_json["threats"] = threats if threats is not None else {}
    base_json["controls"] = controls if controls is not None else {}
    base_json["feature_classes"] = (
        feature_classes if feature_classes is not None else {}
    )
    return ThreatModelData(base_json)


def test_feature_classes_not_fully_related():
    threatmodel_data = create_threatmodel(
        feature_classes={
            "FC1": {"class_relationship": [{"type": "parent", "class": "FC4"}]},
            "FC2": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
            "FC3": {"class_relationship": []},
            "FC4": {"class_relationship": [{"type": "parent", "class": "FC3"}]},
            "FC5": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
            "FC6": {
                "class_relationship": [
                    {"type": "parent", "class": "FC2"},
                    {"type": "parent", "class": "FC7"},
                ]
            },
            "FC7": {"class_relationship": []},
        }
    )
    not_fully_related_fc1 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC1"]
    )
    assert sorted(not_fully_related_fc1) == ["fc3", "fc4", "fc6", "fc7"]

    not_fully_related_fc2 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC2"]
    )
    assert sorted(not_fully_related_fc2) == ["fc1", "fc3", "fc4", "fc5", "fc6", "fc7"]

    not_fully_related_fc3 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC3"]
    )
    assert sorted(not_fully_related_fc3) == ["fc6", "fc7"]

    not_fully_related_fc6 = threatmodel_data.get_feature_classes_not_fully_related(
        ["FC6"]
    )
    assert sorted(not_fully_related_fc6) == ["fc1", "fc2", "fc3", "fc4", "fc5", "fc7"]

    fc1_ancestors = threatmodel_data.get_ancestors_feature_classes("FC1")
    assert sorted(fc1_ancestors) == ["fc3", "fc4"]

    fc1_ancestors = threatmodel_data.get_ancestors_feature_classes("FC6")
    assert sorted(fc1_ancestors) == ["fc1", "fc2", "fc3", "fc4", "fc7"]


def test_get_upstream_dependent_controls():
    threatmodel_data = create_threatmodel(
        controls={"service.c1": {"depends_on": "service.c2"}, "service.c2": {}}
    )
    assert threatmodel_data.get_upstream_dependent_controls("service.c1") == {
        "service.c2": {}
    }


def test_get_downstream_dependent_controls():
    threatmodel_data = create_threatmodel(
        controls={"service.c1": {"depends_on": "service.c2"}, "service.c2": {}}
    )
    assert threatmodel_data.get_downstream_dependent_controls(["service.c2"]) == {
        "service.c1"
    }


def example_threatmodel_json():
    return {
        "metadata": {"name": "Model"},
        "threats": {
            "1": {
                "example_threat": "data",
                "mitigate": [{"threat": "1"}, {"threat": "2"}],
            },
            "2": {"example_threat": "data", "mitigate": [{"threat": "1"}]},
        },
        "feature_classes": {
            "FC1": {"example_feature_class": "data"},
            "FC2": {"example_feature_class": "data"},
        },
        "controls": {
            "control1": {
                "feature_class": ["FC1"],
                "mitigate": [{"threat": "1"}],
                "assured_by": "control2",
            },
            "control2": {
                "feature_class": ["FC2"],
                "mitigate": [{"threat": "2"}],
                "assured_by": "",
            },
        },
        "control_objectives": {},
        "actions": {},
    }


def test_get_controls_for_current_threats():
    threatmodel_data = create_threatmodel(
        feature_classes={
            "FC1": {"class_relationship": []},
            "FC2": {"class_relationship": []},
        },
        threats={"T1": {}, "T2": {}},
        controls={
            "control1": {
                "feature_class": ["FC1"],
                "mitigate": [{"threat": "T1"}],
                "assured_by": "control2",
            },
            "control2": {"feature_class": ["FC1"], "mitigate": [], "assured_by": ""},
            "control3": {
                "feature_class": ["FC3"],
                "mitigate": [{"threat": "T2"}],
                "assured_by": "",
            },
            "control4": {
                "feature_class": ["FC1"],
                "mitigate": [{"threat": "T3"}],
                "assured_by": "",
            },
            "control5": {
                "feature_class": ["FC2"],
                "mitigate": [{"threat": "T2"}],
                "assured_by": "",
            },
        },
    )

    controls = threatmodel_data.get_controls_for_current_threats()

    assert controls == {
        "control1": {
            "feature_class": ["FC1"],
            "mitigate": [{"threat": "T1"}],
            "assured_by": "control2",
        },
        "control2": {"feature_class": ["FC1"], "mitigate": [], "assured_by": ""},
        "control5": {
            "feature_class": ["FC2"],
            "mitigate": [{"threat": "T2"}],
            "assured_by": "",
        },
    }
def test_get_permissions():
    access_data = {
        "AND": ["read_data", {"OPTIONAL": ["optional_read"]}],
        "UNIQUE": "write_data",
        "OPTIONAL": ["optional_write"],
    }

    # Test with add_optional=True
    permissions_with_optional = get_permissions(access_data, add_optional=True)
    assert sorted(permissions_with_optional) == ["optional_read", "optional_write", "read_data", "write_data"]

    # Test with add_optional=False
    permissions_without_optional = get_permissions(access_data, add_optional=False)
    assert sorted(permissions_without_optional) == ["read_data", "write_data"]

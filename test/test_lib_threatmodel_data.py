import pytest

from tmxcaliber.lib.threatmodel_data import ThreatModelData, get_permissions


def create_threatmodel(
    feature_classes=None,
    threats=None,
    controls=None,
    scorecard=None,
    control_objectives=None,
):
    base_json = {
        "metadata": {"name": "Model"},
        "control_objectives": (
            control_objectives if control_objectives is not None else {}
        ),
        "actions": {},
    }
    base_json["threats"] = threats if threats is not None else {}
    base_json["controls"] = controls if controls is not None else {}
    base_json["feature_classes"] = (
        feature_classes if feature_classes is not None else {}
    )
    if scorecard is not None:
        base_json["scorecard"] = scorecard
    return ThreatModelData(base_json)


def reset_threatmodel_data_list():
    ThreatModelData.threatmodel_data_list = []


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
    assert sorted(permissions_with_optional) == [
        "optional_read",
        "optional_write",
        "read_data",
        "write_data",
    ]

    # Test with add_optional=False
    permissions_without_optional = get_permissions(access_data, add_optional=False)
    assert sorted(permissions_without_optional) == ["read_data", "write_data"]


def test_get_csv_of_aws_data_perimeter_controls_basic_extraction():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "Perimeter": ["Service.C1", "Service.C2"],
                "NA": ["Service.C999"],
            }
        },
        controls={
            "Service.C1": {"objective": "S3.CO40", "retired": False},
            "Service.C2": {"objective": "S3.CO40", "retired": False},
        },
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [
        ["objective", "objective_description", "id", "retired"],
        ["S3.CO40", "", "Service.C1", False],
        ["S3.CO40", "", "Service.C2", False],
    ]


def test_get_csv_of_aws_data_perimeter_controls_deduplication():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "CategoryA": ["Service.C1", "Service.C2"],
                "CategoryB": ["Service.C2"],
            }
        },
        controls={
            "Service.C1": {"objective": "S3.CO40", "retired": False},
            "Service.C2": {"objective": "S3.CO40", "retired": False},
        },
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [
        ["objective", "objective_description", "id", "retired"],
        ["S3.CO40", "", "Service.C1", False],
        ["S3.CO40", "", "Service.C2", False],
    ]


def test_get_csv_of_aws_data_perimeter_controls_missing_scorecard():
    reset_threatmodel_data_list()
    create_threatmodel()

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [["id"]]


def test_get_csv_of_aws_data_perimeter_controls_directory_aggregation():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "CategoryA": ["Service.C1", "Service.C3"],
                "CategoryB": ["Service.C2", "Service.C3"],
                "NA": ["Service.C999"],
            }
        },
        controls={
            "Service.C1": {"objective": "CO1", "retired": False},
            "Service.C2": {"objective": "CO1", "retired": False},
            "Service.C3": {"objective": "CO1", "retired": False},
        },
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [
        ["objective", "objective_description", "id", "retired"],
        ["CO1", "", "Service.C1", False],
        ["CO1", "", "Service.C2", False],
        ["CO1", "", "Service.C3", False],
    ]


def test_get_csv_of_aws_data_perimeter_controls_case_insensitive_na():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "NA": ["Service.C2"],
                "CategoryA": ["Service.C3"],
            }
        },
        controls={
            "Service.C3": {"objective": "CO1", "retired": False},
        },
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()
    print(csv_matrix)

    assert csv_matrix == [
        ["objective", "objective_description", "id", "retired"],
        ["CO1", "", "Service.C3", False],
    ]


def test_get_csv_of_aws_data_perimeter_controls_keeps_rows_from_later_models():
    reset_threatmodel_data_list()
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "Perimeter": ["Service.C1"],
            }
        }
    )
    create_threatmodel(
        scorecard={
            "aws_data_perimeter": {
                "Perimeter": ["Service.C1"],
            }
        },
        controls={
            "Service.C1": {"objective": "CO1", "retired": False},
        },
        control_objectives={
            "CO1": {"description": "Objective 1"},
        },
    )

    csv_matrix = ThreatModelData.get_csv_of_aws_data_perimeter_controls()

    assert csv_matrix == [
        ["objective", "objective_description", "id", "retired"],
        ["CO1", "Objective 1", "Service.C1", False],
    ]


def test_get_csv_of_controls_with_ids_filter_inclusive():
    reset_threatmodel_data_list()
    create_threatmodel(
        controls={
            "Service.C1": {"objective": "CO1", "retired": False},
            "Service.C2": {"objective": "CO1", "retired": False},
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_controls(["service.c2"], exclude=False)

    assert csv_matrix[0] == [
        "objective",
        "objective_description",
        "id",
        "retired",
    ]
    assert csv_matrix[1:] == [["CO1", "", "Service.C2", False]]


def test_get_csv_of_controls_with_ids_filter_exclusive():
    reset_threatmodel_data_list()
    create_threatmodel(
        controls={
            "Service.C1": {"objective": "CO1", "retired": False},
            "Service.C2": {"objective": "CO1", "retired": False},
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_controls(["service.c2"], exclude=True)

    assert csv_matrix[0] == [
        "objective",
        "objective_description",
        "id",
        "retired",
    ]
    assert csv_matrix[1:] == [["CO1", "", "Service.C1", False]]


def test_get_csv_of_controls_includes_objective_description_per_file():
    reset_threatmodel_data_list()

    create_threatmodel(
        controls={"Service.C1": {"objective": "Service.CO1", "retired": False}},
        scorecard={},
        control_objectives={"Service.CO1": {"description": "Objective 1"}},
    )

    create_threatmodel(
        controls={"Service.C2": {"objective": "Service.CO2", "retired": False}},
        scorecard={},
        control_objectives={"Service.CO2": {"description": "Objective 2"}},
    )

    csv_matrix = ThreatModelData.get_csv_of_controls()

    # Header
    assert csv_matrix[0] == [
        "objective",
        "objective_description",
        "id",
        "retired",
    ]

    assert ["Service.CO1", "Objective 1", "Service.C1", False] in csv_matrix[1:]
    assert ["Service.CO2", "Objective 2", "Service.C2", False] in csv_matrix[1:]


def test_list_controls_resolver_aws_data_perimeter_exclude_without_ids():
    from tmxcaliber.lib.control_selector import resolve_control_ids
    from tmxcaliber.lib.filter import Filter

    reset_threatmodel_data_list()
    create_threatmodel(
        controls={
            "Service.C1": {"objective": "S3.CO40", "retired": False},
            "Service.C2": {"objective": "S3.CO40", "retired": False},
            "Service.C3": {"objective": "S3.CO41", "retired": False},
        },
        scorecard={
            "aws_data_perimeter": {
                "Perimeter": ["Service.C1", "Service.C2"],
                "NA": ["Service.C999"],
            }
        },
    )

    ids = resolve_control_ids(
        ThreatModelData.threatmodel_data_list,
        list_type="AWS_DATA_PERIMETER",
        filter_obj=Filter(ids=""),
        exclude=True,
        ids_were_provided=False,
    )

    assert ids == ["Service.C3"]


def test_list_controls_resolver_aws_data_perimeter_intersect_control_objective():
    from tmxcaliber.lib.control_selector import resolve_control_ids
    from tmxcaliber.lib.filter import Filter

    reset_threatmodel_data_list()
    create_threatmodel(
        controls={
            "Service.C1": {"objective": "S3.CO40", "retired": False},
            "Service.C2": {"objective": "S3.CO41", "retired": False},
            "Service.C3": {"objective": "S3.CO40", "retired": False},
        },
        scorecard={
            "aws_data_perimeter": {
                "Perimeter": ["Service.C1", "Service.C2", "Service.C3"],
            }
        },
    )

    ids = resolve_control_ids(
        ThreatModelData.threatmodel_data_list,
        list_type="AWS_DATA_PERIMETER",
        filter_obj=Filter(ids="S3.CO40"),
        exclude=False,
        ids_were_provided=True,
    )

    assert ids == ["Service.C1", "Service.C3"]


def test_list_controls_resolver_empty_intersection_does_not_dump_all_controls():
    from tmxcaliber.lib.control_selector import resolve_control_ids
    from tmxcaliber.lib.filter import Filter

    reset_threatmodel_data_list()
    create_threatmodel(
        controls={
            "Service.C1": {"objective": "CO1", "retired": False},
            "Service.C2": {"objective": "CO2", "retired": False},
        },
        control_objectives={
            "CO1": {"description": "Objective 1"},
            "CO2": {"description": "Objective 2"},
        },
        scorecard={"aws_data_perimeter": {}},
    )

    ids = resolve_control_ids(
        ThreatModelData.threatmodel_data_list,
        list_type="AWS_DATA_PERIMETER",
        filter_obj=Filter(),
        exclude=False,
        ids_were_provided=True,
    )

    assert ids == []

    csv_matrix = ThreatModelData.get_csv_of_controls(ids, exclude=False)

    assert csv_matrix == [["objective", "objective_description", "id", "retired"]]

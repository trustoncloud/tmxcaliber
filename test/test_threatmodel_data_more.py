import logging

from tmxcaliber.lib.filter import Filter
from tmxcaliber.lib.filter_applier import FilterApplier
from tmxcaliber.lib.threatmodel_data import (
    ThreatModelData,
    ThreatModelDataList,
    get_permissions,
)


def create_threatmodel(
    *,
    feature_classes=None,
    threats=None,
    controls=None,
    control_objectives=None,
    scorecard=None,
):
    return ThreatModelData(
        {
            "metadata": {"name": "Model"},
            "feature_classes": feature_classes if feature_classes is not None else {},
            "threats": threats if threats is not None else {},
            "controls": controls if controls is not None else {},
            "control_objectives": (
                control_objectives if control_objectives is not None else {}
            ),
            "actions": {},
            "scorecard": scorecard if scorecard is not None else {},
        }
    )


def reset_threatmodel_data_list():
    ThreatModelData.threatmodel_data_list = []


def test_legacy_template_fields_are_upgraded_on_initialization():
    reset_threatmodel_data_list()
    threatmodel = create_threatmodel(
        feature_classes={"Svc.FC1": {"class_relationship": {}}},
        control_objectives={"Svc.CO1": {"scf": "SCF1,SCF2"}},
    )
    threatmodel.threatmodel_json["metadata"]["timestamp"] = "1710000000"
    upgraded = ThreatModelData(threatmodel.threatmodel_json, add_to_list=False)

    assert upgraded.control_objectives["Svc.CO1"]["scf"] == ["SCF1", "SCF2"]
    assert upgraded.feature_classes["Svc.FC1"]["class_relationship"] == []
    assert upgraded.metadata["release"] == "1710000000"


def test_get_feature_classes_not_fully_related_logs_for_missing_feature_classes(caplog):
    reset_threatmodel_data_list()
    threatmodel = create_threatmodel(
        feature_classes={"Svc.FC1": {"class_relationship": []}}
    )

    with caplog.at_level(logging.WARNING):
        result = threatmodel.get_feature_classes_not_fully_related(["Svc.FC999"])

    assert "provided FC id (Svc.FC999) is not present" in caplog.text
    assert result == ["svc.fc1"]


def test_get_permissions_returns_empty_for_non_dict_access():
    assert get_permissions(None) == []
    assert get_permissions(["not", "a", "dict"]) == []


def test_get_controls_for_current_threats_handles_malformed_control_shapes():
    reset_threatmodel_data_list()
    threatmodel = create_threatmodel(
        feature_classes={"Svc.FC1": {"class_relationship": []}},
        threats={"Svc.T1": {}},
        controls={
            "Svc.C1": {
                "feature_class": "Svc.FC1",
                "mitigate": {"threat": "Svc.T1"},
                "assured_by": ["Svc.C2"],
            },
            "Svc.C2": {
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T1"}],
                "assured_by": "",
            },
        },
    )

    assert threatmodel.get_controls_for_current_threats() == {
        "Svc.C2": {
            "feature_class": ["Svc.FC1"],
            "mitigate": [{"threat": "Svc.T1"}],
            "assured_by": "",
        }
    }


def test_threatmodel_data_list_get_csv_serializes_access_values():
    reset_threatmodel_data_list()
    threatmodel = create_threatmodel(
        threats={
            "Svc.T1": {
                "name": "Threat 1",
                "feature_class": "Svc.FC1",
                "access": {"AND": ["perm.read"]},
            }
        }
    )

    output = (
        ThreatModelDataList([threatmodel]).get_csv().getvalue().strip().splitlines()
    )

    assert output[0] == "id,name,feature_class,access"
    assert output[1] == 'Svc.T1,Threat 1,Svc.FC1,"{""AND"": [""perm.read""]}"'


def test_get_csv_of_threats_supports_empty_and_non_empty_states():
    reset_threatmodel_data_list()
    assert ThreatModelData.get_csv_of_threats() == []

    create_threatmodel(
        threats={
            "Svc.T1": {
                "name": "Threat 1",
                "feature_class": "Svc.FC1",
                "access": {"AND": ["perm.read"]},
            }
        }
    )

    csv_matrix = ThreatModelData.get_csv_of_threats()

    assert csv_matrix[0] == ["id", "name", "feature_class", "access"]
    assert csv_matrix[1] == [
        "Svc.T1",
        "Threat 1",
        "Svc.FC1",
        '{"AND": ["perm.read"]}',
    ]


def test_get_csv_of_threats_uses_first_non_empty_filtered_model():
    reset_threatmodel_data_list()

    first_model = create_threatmodel(
        threats={
            "Svc.T1": {
                "name": "Unrelated threat",
                "feature_class": "Svc.FC1",
                "access": {"AND": ["perm.read"]},
            }
        }
    )
    second_model = create_threatmodel(
        threats={
            "Vpc.T73": {
                "name": "Threat 73",
                "feature_class": "Vpc.FC1",
                "access": {"AND": ["ec2:DescribeVpcs"]},
            },
            "Vpc.T74": {
                "name": "Threat 74",
                "feature_class": "Vpc.FC1",
                "access": {"AND": ["ec2:ModifyVpcBlockPublicAccessOptions"]},
            },
        }
    )

    filter_obj = Filter(ids="Vpc.T73,Vpc.T74")
    FilterApplier(filter_obj, exclude_as_filter=False).apply_filter(first_model)
    FilterApplier(filter_obj, exclude_as_filter=False).apply_filter(second_model)

    assert ThreatModelData.get_csv_of_threats() == [
        ["id", "name", "feature_class", "access"],
        ["Vpc.T73", "Threat 73", "Vpc.FC1", '{"AND": ["ec2:DescribeVpcs"]}'],
        [
            "Vpc.T74",
            "Threat 74",
            "Vpc.FC1",
            '{"AND": ["ec2:ModifyVpcBlockPublicAccessOptions"]}',
        ],
    ]


def test_get_csv_of_controls_empty_shapes_return_empty_matrices():
    reset_threatmodel_data_list()
    assert ThreatModelData.get_csv_of_controls() == []

    reset_threatmodel_data_list()
    model = create_threatmodel()
    assert ThreatModelData.get_csv_of_controls() == []
    assert (
        ThreatModelData._get_csv_of_controls_from_controls_dict(
            [model], controls_by_tm=[{}]
        )
        == []
    )


def test_get_csv_of_aws_data_perimeter_controls_handles_invalid_scorecards_and_filters():
    reset_threatmodel_data_list()
    create_threatmodel(scorecard={"aws_data_perimeter": "invalid"})
    assert ThreatModelData.get_csv_of_aws_data_perimeter_controls() == [["id"]]

    reset_threatmodel_data_list()
    create_threatmodel(
        controls={
            "Svc.C1": {"objective": "Svc.CO1", "retired": False},
            "Svc.C2": {"objective": "Svc.CO2", "retired": False},
        },
        control_objectives={
            "Svc.CO1": {"description": "Objective 1"},
            "Svc.CO2": {"description": "Objective 2"},
        },
        scorecard={"aws_data_perimeter": {"Perimeter": ["Svc.C1", "Svc.C2"]}},
    )

    assert ThreatModelData.get_csv_of_aws_data_perimeter_controls(
        ["svc.c2"], exclude=False
    ) == [
        ["objective", "objective_description", "id", "retired"],
        ["Svc.CO2", "Objective 2", "Svc.C2", False],
    ]
    assert ThreatModelData.get_csv_of_aws_data_perimeter_controls(
        ["svc.c2"], exclude=True
    ) == [
        ["objective", "objective_description", "id", "retired"],
        ["Svc.CO1", "Objective 1", "Svc.C1", False],
    ]

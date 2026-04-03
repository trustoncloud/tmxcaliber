from tmxcaliber.lib.filter import Filter
from tmxcaliber.lib.filter_applier import FilterApplier
from tmxcaliber.lib.threatmodel_data import ThreatModelData


def create_threatmodel(
    feature_classes: dict,
    threats: dict | None = None,
    controls: dict | None = None,
    control_objectives: dict | None = None,
    actions: dict | None = None,
) -> ThreatModelData:
    base_json = {
        "metadata": {"name": "Model"},
        "feature_classes": feature_classes,
        "threats": threats or {},
        "controls": controls or {},
        "control_objectives": control_objectives or {},
        "actions": actions or {},
    }
    return ThreatModelData(base_json, add_to_list=False)


def create_connected_threatmodel() -> ThreatModelData:
    return create_threatmodel(
        feature_classes={
            "Someservice.FC1": {"class_relationship": []},
            "Someservice.FC5": {
                "class_relationship": [{"type": "parent", "class": "Someservice.FC1"}]
            },
            "Someservice.FC8": {
                "class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]
            },
            "Someservice.FC10": {
                "class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]
            },
            "Someservice.FC11": {
                "class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]
            },
            "Someservice.FC19": {
                "class_relationship": [
                    {"type": "parent", "class": "Someservice.FC8"},
                    {"type": "parent", "class": "Someservice.FC10"},
                ]
            },
        },
        threats={
            "Someservice.T1": {"feature_class": "Someservice.FC8"},
            "Someservice.T2": {"feature_class": "Someservice.FC10"},
            "Someservice.T3": {"feature_class": "Someservice.FC11"},
        },
        controls={
            "Someservice.C1": {
                "objective": "Someservice.CO1",
                "coso": "Preventive",
                "feature_class": ["Someservice.FC8", "Someservice.FC10"],
                "mitigate": [
                    {"threat": "Someservice.T1"},
                    {"threat": "Someservice.T2"},
                ],
                "assured_by": "Someservice.C3,Someservice.C4",
            },
            "Someservice.C2": {
                "objective": "Someservice.CO2",
                "coso": "Preventive",
                "feature_class": ["Someservice.FC11"],
                "mitigate": [{"threat": "Someservice.T3"}],
            },
            "Someservice.C3": {
                "objective": "Someservice.CO3",
                "coso": "Assurance",
                "feature_class": ["Someservice.FC8", "Someservice.FC10"],
                "mitigate": [],
            },
            "Someservice.C4": {
                "objective": "Someservice.CO4",
                "coso": "Assurance",
                "feature_class": ["Someservice.FC8", "Someservice.FC10"],
                "mitigate": [],
            },
        },
        control_objectives={
            "Someservice.CO1": {},
            "Someservice.CO2": {},
            "Someservice.CO3": {},
            "Someservice.CO4": {},
        },
        actions={
            "Someservice.A1": {"feature_class": "Someservice.FC8"},
            "Someservice.A2": {"feature_class": "Someservice.FC10"},
            "Someservice.A3": {"feature_class": "Someservice.FC11"},
        },
    )


class TestFilterApplier:

    def test_fc_filter(self):
        threatmodel_data = create_connected_threatmodel()
        filter_to_apply = Filter(ids="Someservice.FC10,someservice.Fc8")
        filter_applier = FilterApplier(filter=filter_to_apply, exclude_as_filter=False)
        filter_applier.apply_filter(threatmodel_data)

        expected_classes = [
            "Someservice.FC1",
            "Someservice.FC5",
            "Someservice.FC8",
            "Someservice.FC10",
        ]
        assert list(threatmodel_data.feature_classes.keys()) == expected_classes
        assert set(threatmodel_data.threats.keys()) == {
            "Someservice.T1",
            "Someservice.T2",
        }
        assert set(threatmodel_data.controls.keys()) == {
            "Someservice.C1",
            "Someservice.C3",
            "Someservice.C4",
        }
        assert threatmodel_data.controls["Someservice.C1"]["feature_class"] == [
            "Someservice.FC8",
            "Someservice.FC10",
        ]
        assert threatmodel_data.controls["Someservice.C1"]["mitigate"] == [
            {"threat": "Someservice.T1"},
            {"threat": "Someservice.T2"},
        ]
        assert (
            threatmodel_data.controls["Someservice.C1"]["assured_by"]
            == "Someservice.C3,Someservice.C4"
        )
        assert set(threatmodel_data.control_objectives.keys()) == {
            "Someservice.CO1",
            "Someservice.CO3",
            "Someservice.CO4",
        }
        assert set(threatmodel_data.actions.keys()) == {
            "Someservice.A1",
            "Someservice.A2",
        }

    def test_fc_exclude_filter(self):
        threatmodel_data = create_connected_threatmodel()
        filter_to_apply = Filter(ids="SomeservicE.Fc8")
        filter_applier = FilterApplier(filter=filter_to_apply, exclude_as_filter=True)
        filter_applier.apply_filter(threatmodel_data)

        expected_classes = [
            "Someservice.FC1",
            "Someservice.FC5",
            "Someservice.FC10",
            "Someservice.FC11",
            "Someservice.FC19",
        ]
        assert list(threatmodel_data.feature_classes.keys()) == expected_classes
        assert {
            "type": "parent",
            "class": "Someservice.FC10",
        } in threatmodel_data.feature_classes["Someservice.FC19"]["class_relationship"]
        assert {
            "type": "parent",
            "class": "Someservice.FC8",
        } not in threatmodel_data.feature_classes["Someservice.FC19"][
            "class_relationship"
        ]

        assert set(threatmodel_data.threats.keys()) == {
            "Someservice.T2",
            "Someservice.T3",
        }
        assert set(threatmodel_data.controls.keys()) == {
            "Someservice.C1",
            "Someservice.C2",
            "Someservice.C3",
            "Someservice.C4",
        }
        assert threatmodel_data.controls["Someservice.C1"]["feature_class"] == [
            "Someservice.FC10"
        ]
        assert threatmodel_data.controls["Someservice.C1"]["mitigate"] == [
            {"threat": "Someservice.T2"}
        ]
        assert threatmodel_data.controls["Someservice.C3"]["feature_class"] == [
            "Someservice.FC10"
        ]
        assert threatmodel_data.controls["Someservice.C4"]["feature_class"] == [
            "Someservice.FC10"
        ]
        assert (
            threatmodel_data.controls["Someservice.C1"]["assured_by"]
            == "Someservice.C3,Someservice.C4"
        )
        assert set(threatmodel_data.control_objectives.keys()) == {
            "Someservice.CO1",
            "Someservice.CO2",
            "Someservice.CO3",
            "Someservice.CO4",
        }
        assert set(threatmodel_data.actions.keys()) == {
            "Someservice.A2",
            "Someservice.A3",
        }

        threatmodel_data = create_connected_threatmodel()
        filter_to_apply = Filter(ids="Someservice.FC10,Someservice.FC8")
        filter_applier = FilterApplier(filter=filter_to_apply, exclude_as_filter=True)
        filter_applier.apply_filter(threatmodel_data)

        expected_classes = ["Someservice.FC1", "Someservice.FC5", "Someservice.FC11"]
        assert list(threatmodel_data.feature_classes.keys()) == expected_classes
        assert set(threatmodel_data.threats.keys()) == {"Someservice.T3"}
        assert set(threatmodel_data.controls.keys()) == {"Someservice.C2"}
        assert set(threatmodel_data.control_objectives.keys()) == {"Someservice.CO2"}
        assert set(threatmodel_data.actions.keys()) == {"Someservice.A3"}

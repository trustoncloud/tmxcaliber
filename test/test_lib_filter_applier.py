import pytest
from tmxcaliber.lib.threatmodel_data import ThreatModelData
from tmxcaliber.lib.filter_applier import FilterApplier
from tmxcaliber.lib.filter import Filter

def create_threatmodel(feature_classes):
    base_json = {
        "metadata": {"name": "Model"},
        "threats": {},
        "controls": {},
        "control_objectives": {},
        "actions": {}
    }
    base_json["feature_classes"] = feature_classes
    return ThreatModelData(base_json)

class TestFilterApplier:

    def test_fc_filter(self):
        threatmodel_data = create_threatmodel({
                "Someservice.FC1": {"class_relationship": []},
                "Someservice.FC5": {"class_relationship": [{"type": "parent", "class": "Someservice.FC1"}]},
                "Someservice.FC8": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC10": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC11": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC19": {"class_relationship": [{"type": "parent", "class": "Someservice.FC8"}, {"type": "parent", "class": "Someservice.FC10"}]},
            })
        filter_to_apply = Filter(ids='Someservice.FC10,Someservice.FC8')
        filter_applier = FilterApplier(filter=filter_to_apply, exclude_as_filter=False)
        filter_applier.apply_filter(threatmodel_data)
        expected_classes = ['Someservice.FC1', 'Someservice.FC5', 'Someservice.FC8', 'Someservice.FC10']
        assert list(threatmodel_data.feature_classes.keys()) == expected_classes

    def test_fc_exclude_filter(self):
        threatmodel_data = create_threatmodel({
                "Someservice.FC1": {"class_relationship": []},
                "Someservice.FC5": {"class_relationship": [{"type": "parent", "class": "Someservice.FC1"}]},
                "Someservice.FC8": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC10": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC11": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC19": {"class_relationship": [{"type": "parent", "class": "Someservice.FC8"}, {"type": "parent", "class": "Someservice.FC10"}]},
            })
        filter_to_apply = Filter(ids='Someservice.FC8')
        filter_applier = FilterApplier(filter=filter_to_apply, exclude_as_filter=True)
        filter_applier.apply_filter(threatmodel_data)
        expected_classes = ['Someservice.FC1', 'Someservice.FC5', 'Someservice.FC10', 'Someservice.FC11', 'Someservice.FC19']
        assert list(threatmodel_data.feature_classes.keys()) == expected_classes
        assert {"type": "parent", "class": "Someservice.FC10"} in threatmodel_data.feature_classes["Someservice.FC19"]["class_relationship"]
        assert {"type": "parent", "class": "Someservice.FC8"} not in threatmodel_data.feature_classes["Someservice.FC19"]["class_relationship"]

        threatmodel_data = create_threatmodel({
                "Someservice.FC1": {"class_relationship": []},
                "Someservice.FC5": {"class_relationship": [{"type": "parent", "class": "Someservice.FC1"}]},
                "Someservice.FC8": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC10": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC11": {"class_relationship": [{"type": "parent", "class": "Someservice.FC5"}]},
                "Someservice.FC19": {"class_relationship": [{"type": "parent", "class": "Someservice.FC8"}, {"type": "parent", "class": "Someservice.FC10"}]},
            })
        filter_to_apply = Filter(ids='Someservice.FC10,Someservice.FC8')
        filter_applier = FilterApplier(filter=filter_to_apply, exclude_as_filter=True)
        filter_applier.apply_filter(threatmodel_data)
        expected_classes = ['Someservice.FC1', 'Someservice.FC5', 'Someservice.FC11']
        assert list(threatmodel_data.feature_classes.keys()) == expected_classes
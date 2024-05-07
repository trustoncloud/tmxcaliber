import pytest
import copy
from tmxcaliber.lib.threatmodel_data import ThreatModelData

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

class TestThreatModelData:

    def test_get_child_feature_classes(self):

        threatmodel_data = create_threatmodel({
                "FC1": {"class_relationship": [{"type": "parent", "class": "FC4"}]},
                "FC2": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
                "FC3": {"class_relationship": []},
                "FC4": {"class_relationship": [{"type": "parent", "class": "FC3"}]},
                "FC5": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
                "FC6": {"class_relationship": [{"type": "parent", "class": "FC2"}]}
            })
        # Test getting children of feature class "FC1"
        children_fc1 = threatmodel_data.get_child_feature_classes("FC1")
        assert sorted(children_fc1) == ['FC1', 'FC2', 'FC5', 'FC6']

        # Test getting children of feature class "FC2"
        children_fc2 = threatmodel_data.get_child_feature_classes("FC2")
        assert sorted(children_fc2) == ['FC2', 'FC6']

        # Test getting children of feature class "FC3"
        children_fc0 = threatmodel_data.get_child_feature_classes("FC3")
        assert sorted(children_fc0) == ['FC1', 'FC2', 'FC3', 'FC4', 'FC5', 'FC6']
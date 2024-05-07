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

    def test_feature_classes_not_fully_related(self):

        threatmodel_data = create_threatmodel({
                "FC1": {"class_relationship": [{"type": "parent", "class": "FC4"}]},
                "FC2": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
                "FC3": {"class_relationship": []},
                "FC4": {"class_relationship": [{"type": "parent", "class": "FC3"}]},
                "FC5": {"class_relationship": [{"type": "parent", "class": "FC1"}]},
                "FC6": {"class_relationship": [{"type": "parent", "class": "FC2"}]},
                "FC7": {"class_relationship": []},
            })
        # Test getting children of feature class "FC1"
        not_fully_related_fc1 = threatmodel_data.get_feature_classes_not_fully_related(["FC1"])
        assert sorted(not_fully_related_fc1) == ['fc3', 'fc4', 'fc7']

        # Test getting children of feature class "FC2"
        not_fully_related_fc2 = threatmodel_data.get_feature_classes_not_fully_related(["FC2"])
        assert sorted(not_fully_related_fc2) == ['fc1', 'fc3', 'fc4', 'fc5', 'fc7']

        # Test getting children of feature class "FC3"
        not_fully_related_fc3 = threatmodel_data.get_feature_classes_not_fully_related(["FC3"])
        assert sorted(not_fully_related_fc3) == ['fc7']
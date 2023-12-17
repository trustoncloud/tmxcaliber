
from collections import OrderedDict

class ThreatModelData:
    def __init__(self, threatmodel_json):
        self.threatmodel_json = threatmodel_json
        self.threats = threatmodel_json.get("threats")
        self.feature_classes = threatmodel_json.get("feature_classes")
        self.controls = threatmodel_json.get("controls")
        self.control_objectives = threatmodel_json.get("control_objectives")
        self.actions = threatmodel_json.get("actions")
    
    def get_json(self):
        json_data = OrderedDict([
            ("threats", self.threats),
            ("feature_classes", self.feature_classes),
            ("controls", self.controls),
            ("control_objectives", self.control_objectives),
            ("actions", self.actions)
        ])
        # Add all other keys from threatmodel_json that are not explicitly mentioned
        for key, value in self.threatmodel_json.items():
            if key not in json_data:
                json_data[key] = value
        return json_data

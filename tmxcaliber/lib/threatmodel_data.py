
class ThreatModelData:
    def __init__(self, threatmodel_json):
        self.threatmodel_json = threatmodel_json
        self.threats = threatmodel_json.get("threats")
        self.feature_classes = threatmodel_json.get("feature_classes")
        self.controls = threatmodel_json.get("controls")
        self.control_objectives = threatmodel_json.get("control_objectives")
        self.actions = threatmodel_json.get("actions")
    
    def get_json(self):
        json_data = {}
        # Iterate over the keys of the original threatmodel_json
        for key, value in self.threatmodel_json.items():
            if key == "threats":
                json_data[key] = self.threats
            elif key == "feature_classes":
                json_data[key] = self.feature_classes
            elif key == "controls":
                json_data[key] = self.controls
            elif key == "control_objectives":
                json_data[key] = self.control_objectives
            elif key == "actions":
                json_data[key] = self.actions
            else:
                json_data[key] = value
        return json_data

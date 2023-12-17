
class ThreatModelData:
    def __init__(self, threatmodel_json):
        self.threatmodel_json = threatmodel_json
        self.threats = threatmodel_json.get("threats")
        self.feature_classes = threatmodel_json.get("feature_classes")
        self.controls = threatmodel_json.get("controls")
        self.control_objectives = threatmodel_json.get("control_objectives")
        self.actions = threatmodel_json.get("actions")

    def get_feature_class_hierarchy(self, feature_class_id_to_filter) -> dict:
        def build_hierarchy(class_id, hierarchy):
            if class_id not in hierarchy:
                hierarchy.add(class_id)
                for relation in self.feature_classes[class_id]["class_relationship"]:
                    if relation["type"] == "parent":
                        build_hierarchy(relation["class"], hierarchy)

        hierarchy = set()
        build_hierarchy(feature_class_id_to_filter, hierarchy)
        return list(hierarchy)

    def get_feature_classes_for_current_threats(self) -> list:
        feature_classes = {
            key: value for key, value in self.feature_classes.items()
            if key in [threat["feature_class"] for threat in self.threats.values()]
        }
        feature_classes_ids = []
        for feature_class_id, feature_class in feature_classes.items():
            if feature_class_id not in feature_classes_ids:
                feature_classes_ids.append(feature_class_id)
            for relation in feature_class["class_relationship"]:
                if relation["type"] != "parent":
                    continue
                class_name = relation["class"]
                if class_name not in feature_classes_ids:
                    feature_classes_ids.append(class_name)
        return feature_classes_ids

    def get_controls_for_current_threats(self) -> dict:
        controls = {}
        threat_ids = set(self.threats.keys())
        for control_id, control in self.controls.items():
            # Check if the control's feature class is in the list of feature classes
            if any(fc in control["feature_class"] for fc in self.feature_classes):
                # Check if any mitigation in the control is related to the threats we have
                if any(mitigation.get("threat") in threat_ids for mitigation in control.get("mitigate", [])):
                    controls[control_id] = control
        return controls
    
    def get_json(self) -> dict:
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

import io
import csv
import json
from .tools import sort_by_id

class ThreatModelDataList:

    def __init__(self, threatmodel_data_list):
        self.threatmodel_data_list = threatmodel_data_list
    
    def get_csv(self):
        output = io.StringIO()
        fieldnames = ['id'] + list(self.threatmodel_data_list[0].get_json()['threats'][next(iter(self.threatmodel_data_list[0].get_json()['threats']))].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for threatmodel_data in self.threatmodel_data_list:
            threats = threatmodel_data.threats
            for key, value in threats.items():
                value['access'] = json.dumps(value['access'])
                writer.writerow({'id': key, **value})
        return output

def get_permissions(access: dict) -> list:
    permissions = []
    for _, perms in access.items():
        if isinstance(perms, str):
            permissions.append(perms)
        elif isinstance(perms, list):
            for perm in perms:
                if isinstance(perm, str):
                    permissions.append(perm)
                elif isinstance(perm, dict):
                    permissions.extend(get_permissions(perm))
    return [x.lower() for x in list(set(permissions))]

def upgrade_to_latest_template_version(tm_json):
    for co in tm_json.get("control_objectives"):
        co_data = tm_json['control_objectives'][co]
        if co_data.get('scf') and isinstance(co_data['scf'], str):
            tm_json['control_objectives'][co]['scf'] = co_data['scf'].split(",")
    return tm_json

class ThreatModelData:

    threatmodel_data_list = []

    def __init__(self, threatmodel_json):
        self.threatmodel_json = upgrade_to_latest_template_version(threatmodel_json)
        self.metadata = self.threatmodel_json.get("metadata")
        self.threats = self.threatmodel_json.get("threats")
        self.feature_classes = self.threatmodel_json.get("feature_classes")
        self.controls = self.threatmodel_json.get("controls")
        self.control_objectives = self.threatmodel_json.get("control_objectives")
        self.actions = self.threatmodel_json.get("actions")
        ThreatModelData.threatmodel_data_list.append(self)

    def get_feature_class_hierarchy(self, feature_class_id_to_filter) -> list:

        actual_feature_class_id_to_filter = None
        for fc in self.feature_classes.keys():
            if fc.lower() == feature_class_id_to_filter.lower():
                actual_feature_class_id_to_filter = fc
                break
        
        if not actual_feature_class_id_to_filter:
            raise ValueError(f'[ERROR] The provided FC id ({feature_class_id_to_filter}) is not present. Make sure to write the full ID, (e.g., Route53.FC1)')

        if actual_feature_class_id_to_filter not in self.feature_classes:
            raise ValueError(f'[ERROR] The provided FC id ({feature_class_id_to_filter}) is not present. Make sure to write the full ID, (e.g., Route53.FC1)')

        def build_hierarchy(class_id, hierarchy):
            if class_id not in hierarchy:
                hierarchy.insert(0, class_id)
                for relation in self.feature_classes[class_id]["class_relationship"]:
                    if relation["type"] == "parent":
                        build_hierarchy(relation["class"], hierarchy)

        hierarchy = []
        build_hierarchy(actual_feature_class_id_to_filter, hierarchy)
        return list(hierarchy)

    def get_child_feature_classes(self, parent_feature_class_id):
        child_fcs = set()
        for fc in self.feature_classes.keys():
            fc_hierarchy = self.get_feature_class_hierarchy(fc)
            if parent_feature_class_id in fc_hierarchy:
                child_fcs.add(fc)
        return list(child_fcs)

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

    @classmethod
    def get_csv_of_threats(cls):
        output = io.StringIO()
        if not cls.threatmodel_data_list:
            return output.getvalue()
        fieldnames = ['id'] + list(cls.threatmodel_data_list[0].get_json()['threats'][next(iter(cls.threatmodel_data_list[0].get_json()['threats']))].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for threatmodel_data in cls.threatmodel_data_list:
            threats = threatmodel_data.threats
            for key, value in threats.items():
                value['access'] = json.dumps(value['access'])
                writer.writerow({'id': key, **value})
        return output.getvalue()

    @classmethod
    def get_csv_of_controls(cls):
        output = io.StringIO()
        if not cls.threatmodel_data_list:
            return output.getvalue()

        control_objectives = cls.threatmodel_data_list[0].get_json()['control_objectives']
        controls = cls.threatmodel_data_list[0].get_json()['controls']

        # Generate initial field names from the controls, excluding 'id' for now
        all_fieldnames = [field for field in controls[next(iter(controls))].keys() if field not in ('id', 'objective', 'objective_description', 'retired')]
        
        # Start with 'objective' and 'objective_description', add 'id' third
        ordered_fieldnames = ['objective', 'objective_description', 'id']
        
        # Add the rest of the fields except for 'retired', which will be added last
        ordered_fieldnames += all_fieldnames
        
        # Append 'retired' to the end
        ordered_fieldnames.append('retired')

        writer = csv.DictWriter(output, fieldnames=ordered_fieldnames)
        writer.writeheader()

        for threatmodel_data in cls.threatmodel_data_list:
            controls = threatmodel_data.get_json()['controls']
            for key, value in controls.items():
                # Fetch the description for the control's objective
                co_description = control_objectives[value['objective']]['description']
                # Include 'objective_description' with its value
                value['objective_description'] = co_description
                # Assign 'id' its value
                value['id'] = key
                # Ensure each row is ordered as per 'ordered_fieldnames'
                row = {fieldname: value.get(fieldname, '') for fieldname in ordered_fieldnames}
                writer.writerow(row)

        return output.getvalue()

def get_classified_cvssed_control_ids_by_co(
    control_id_by_cvss_severity: "dict[str, list]",
    control_obj_id: str,
    control_data: dict
) -> "dict[str, list]":
    severity_range = ("Very High", "High", "Medium", "Low", "Very Low")
    control_id_list = {}

    for idx, severity in enumerate(severity_range):
        if control_id_by_cvss_severity:
            control_id_list[severity] = control_id_by_cvss_severity[severity]
        else:
            control_id_list[severity] = []
        for control in control_data:
            if control_data[control]["objective"] != control_obj_id:
                continue
            if control_data[control]["weighted_priority"] != severity:
                continue
            add_control = True
            if control in control_id_list[severity]:
                add_control = False
            if idx > 0:
                for severity_prev in severity_range[0:idx]:
                    if control in control_id_list[severity_prev]:
                        add_control = False 
            if add_control:
                control_id_list[severity].append(control)
        control_id_list[severity] = sort_by_id(control_id_list[severity])  
    return control_id_list
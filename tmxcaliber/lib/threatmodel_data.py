import io
import csv
import json
import copy
from .tools import sort_by_id, apply_json_filter

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
        upgraded_json = upgrade_to_latest_template_version(threatmodel_json)
        self.threatmodel_json_original = copy.deepcopy(upgraded_json)
        self.threatmodel_json = upgraded_json
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
    
    def get_upstream_controls(self, control_id) -> dict:

        def get_all_dependencies(controls, control_id, seen=None):
            if seen is None:
                seen = set()
            
            # Get the current control's data
            control_data = controls.get(control_id, {})
            depends_on = control_data.get('depends_on')
            # Check if depends_on contains multiple control IDs separated by commas
            if depends_on:
                depends_on_ids = depends_on.split(',')
                for depends_on_id in depends_on_ids:
                    depends_on_id = depends_on_id.strip()  # Clean up any whitespace
                    if depends_on_id and depends_on_id not in seen:
                        seen.add(depends_on_id)
                        get_all_dependencies(controls, depends_on_id, seen)
            
            return seen
        
        controls = {}
        for control_dependency_id in get_all_dependencies(self.controls, control_id):
            controls[control_dependency_id] = self.controls[control_dependency_id]
        return controls

    def get_downstream_controls(self, control_ids) -> dict:

        def build_reverse_dependencies(controls):
            reverse_deps = {}
            for ctrl_id, ctrl_data in controls.items():
                depends_on = ctrl_data.get('depends_on')
                if depends_on:
                    depends_on_ids = [dep_id.strip() for dep_id in depends_on.split(',')]
                    for dep_id in depends_on_ids:
                        if dep_id not in reverse_deps:
                            reverse_deps[dep_id] = []
                        reverse_deps[dep_id].append(ctrl_id)
            return reverse_deps

        def find_all_dependents(reverse_deps, initial_controls, all_controls, seen=None):
            if seen is None:
                seen = set()

            # Initialize the search with all initial controls
            stack = list(initial_controls)

            while stack:
                current_control = stack.pop()
                if current_control in reverse_deps:
                    for dependent in reverse_deps[current_control]:
                        if dependent not in seen:
                            # Check if all dependencies of 'dependent' are in 'seen' or are among the initial controls
                            dependent_data = all_controls[dependent]
                            if 'depends_on' in dependent_data and dependent_data['depends_on']:
                                dependent_dependencies = [dep.strip() for dep in dependent_data['depends_on'].split(',')]
                                if all(dep in seen or dep in initial_controls for dep in dependent_dependencies):
                                    seen.add(dependent)
                                    stack.append(dependent)
                            else:
                                # If no dependencies, we can add directly
                                seen.add(dependent)
                                stack.append(dependent)

            return seen
    
        reverse_dependencies = build_reverse_dependencies(self.controls)
        all_dependents = find_all_dependents(reverse_dependencies, control_ids, self.controls)
        return all_dependents

    def get_excluded_output(self) -> dict:
        return apply_json_filter(self.threatmodel_json_original, self.get_json())

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
        if not cls.threatmodel_data_list or not cls.threatmodel_data_list[0].get_json()['threats']:
            return []
        fieldnames = ['id'] + list(cls.threatmodel_data_list[0].get_json()['threats'][next(iter(cls.threatmodel_data_list[0].get_json()['threats']))].keys())
        csv_matrix = []
        csv_matrix.append(fieldnames)
        for threatmodel_data in cls.threatmodel_data_list:
            threats = threatmodel_data.threats
            for key, value in threats.items():
                value['id'] = key
                value['access'] = json.dumps(value['access'])
                row = [value.get(fieldname, '') for fieldname in fieldnames]
                csv_matrix.append(row)
        return csv_matrix

    @classmethod
    def get_csv_of_controls(cls):
        if not cls.threatmodel_data_list or not cls.threatmodel_data_list[0].get_json()['controls']:
            return []

        control_objectives = cls.threatmodel_data_list[0].get_json()['control_objectives']
        controls = cls.threatmodel_data_list[0].get_json()['controls']

        # Generate initial field names from the controls, excluding 'id' for now
        all_fieldnames = [field for field in controls[next(iter(controls))].keys() if field not in ('id', 'objective', 'objective_description', 'retired')]
        
        # Start with 'objective' and 'objective_description', add 'id' third
        ordered_fieldnames = ['objective', 'objective_description', 'id']
        ordered_fieldnames += all_fieldnames
        ordered_fieldnames.append('retired')

        csv_matrix = []
        csv_matrix.append(ordered_fieldnames)

        for threatmodel_data in cls.threatmodel_data_list:
            controls = threatmodel_data.get_json()['controls']
            for key, value in controls.items():
                co_description = control_objectives[value['objective']]['description']
                value['objective_description'] = co_description
                value['id'] = key
                row = [value.get(fieldname, '') for fieldname in ordered_fieldnames]
                csv_matrix.append(row)
        return csv_matrix

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
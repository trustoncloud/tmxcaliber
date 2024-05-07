from .filter import Filter
from .threatmodel_data import ThreatModelData, get_permissions

SEVERITY_ORDER = ("very high", "high", "medium", "low", "very low")

class FilterApplier:
    def __init__(self, filter: Filter, exclude_as_filter: bool):
        self.filter = filter
        self.exclude_as_filter = exclude_as_filter

    def apply_filter(self, threatmodel_data: ThreatModelData):
        if self.filter.severity:
            self.__filter_by_severity(threatmodel_data=threatmodel_data)
        if self.filter.feature_classes:
            self.__filter_by_feature_class(threatmodel_data=threatmodel_data)
        if self.filter.threats:
            self.__filter_by_threats(threatmodel_data=threatmodel_data)
        if self.filter.controls:
            self.__filter_by_controls(self.filter.controls, threatmodel_data=threatmodel_data)
        if self.filter.control_objectives:
            self.__filter_by_control_objectives(threatmodel_data=threatmodel_data)
        if self.filter.permissions:
            self.__filter_by_permissions(threatmodel_data=threatmodel_data)
    
    def __filter_by_severity(self, threatmodel_data: ThreatModelData):
        severity_index = SEVERITY_ORDER.index(self.filter.severity)
        allowed_severities = set(severity.lower() for severity in SEVERITY_ORDER[:severity_index + 1])
        if self.exclude_as_filter:
            for threat_id, threat in threatmodel_data.threats.copy().items():
                if threat.get("cvss_severity", "").lower() in allowed_severities:
                    threatmodel_data.threats.pop(threat_id)
        else: 
            for threat_id, threat in threatmodel_data.threats.copy().items():
                if threat.get("cvss_severity", "").lower() not in allowed_severities:
                    threatmodel_data.threats.pop(threat_id)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

    def __filter_controls_by_current_threats(self, threatmodel_data: ThreatModelData):
        active_controls = threatmodel_data.get_controls_for_current_threats()
        for control_id, control in threatmodel_data.controls.copy().items():
            if control_id not in active_controls:
                threatmodel_data.controls.pop(control_id)
            mitigations_with_current_threats = []
            for mitigation in control['mitigate']:
                if mitigation['threat'] in threatmodel_data.threats:
                    mitigations_with_current_threats.append(mitigation)
            control['mitigate'] = mitigations_with_current_threats
        self.__filter_orphan_assurance_controls(threatmodel_data)

    def __filter_control_objectives_by_current_controls(self, threatmodel_data: ThreatModelData):
        active_control_objectives = [value['objective'] for value in threatmodel_data.controls.values()]
        for co_id, _ in threatmodel_data.control_objectives.copy().items():
            if co_id not in active_control_objectives:
                threatmodel_data.control_objectives.pop(co_id)
    
    def __filter_controls_by_current_control_objectives(self, threatmodel_data: ThreatModelData):
        for control_id, control in threatmodel_data.controls.copy().items():
            if control['objective'] not in threatmodel_data.control_objectives:
                threatmodel_data.controls.pop(control_id)
        self.__filter_orphan_assurance_controls(threatmodel_data)

    def __filter_actions_by_current_feature_classes(self, threatmodel_data: ThreatModelData):
        for action_id, action in threatmodel_data.actions.copy().items():
            if action['feature_class'] not in threatmodel_data.feature_classes:
                threatmodel_data.actions.pop(action_id)
    
    def __filter_by_feature_class(self, threatmodel_data: ThreatModelData):
        if self.exclude_as_filter:
            not_fully_related_fcs = threatmodel_data.get_feature_classes_not_fully_related(self.filter.feature_classes)
            for feature_class in threatmodel_data.feature_classes.copy():
                if feature_class.lower() not in not_fully_related_fcs or feature_class.lower() in self.filter.feature_classes:
                    threatmodel_data.feature_classes.pop(feature_class)
        else:
            feature_class_ids_to_keep = []
            for filtered_fc in self.filter.feature_classes:
                feature_class_ids_to_keep.append(filtered_fc)
                ancestor_fc_ids = threatmodel_data.get_ancestors_feature_classes(filtered_fc)
                for fc_id in ancestor_fc_ids:
                    if fc_id not in feature_class_ids_to_keep:
                        feature_class_ids_to_keep.append(fc_id)
            for fc_id in threatmodel_data.feature_classes.copy():
                if fc_id.lower() not in feature_class_ids_to_keep:
                    threatmodel_data.feature_classes.pop(fc_id)

        self.__filter_relationships_by_current_feature_classes(threatmodel_data)
        self.__filter_threats_by_current_feature_classes(threatmodel_data)
        self.__filter_controls_by_current_feature_classes(threatmodel_data)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

    def __filter_relationships_by_current_feature_classes(self, threatmodel_data: ThreatModelData):
        for _, feature_class in threatmodel_data.feature_classes.items():
            relations_to_keep = []
            for relation in feature_class['class_relationship']:
                if relation.get('class') in threatmodel_data.feature_classes:
                    relations_to_keep.append(relation)
            feature_class['class_relationship'] = relations_to_keep

    def __filter_threats_by_current_feature_classes(self, threatmodel_data: ThreatModelData):
        for threat_id, threat in threatmodel_data.threats.copy().items():
            if threat.get("feature_class") not in threatmodel_data.feature_classes:
                threatmodel_data.threats.pop(threat_id)

    def __filter_controls_by_current_feature_classes(self, threatmodel_data: ThreatModelData):
        for control_id, control in threatmodel_data.controls.copy().items():
            for feature_class in control.get("feature_class").copy():
                if feature_class not in threatmodel_data.feature_classes:
                    threatmodel_data.controls[control_id]["feature_class"].remove(feature_class)

    def __filter_by_permissions(self, threatmodel_data: ThreatModelData):
        for threat_id, threat in threatmodel_data.threats.copy().items():
            has_access = False
            permissions = get_permissions(threat.get("access"))
            # Determine if any of the specified permissions match the threat's permissions
            if any(permission.lower() in [filter_permission.lower() for filter_permission in self.filter.permissions] for permission in permissions):
                has_access = True
            # Apply the exclusion or inclusion logic based on the exclude_as_filter flag
            if self.exclude_as_filter:
                if has_access:
                    threatmodel_data.threats.pop(threat_id)
            else:
                if not has_access:
                    threatmodel_data.threats.pop(threat_id)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

    def __filter_by_threats(self, threatmodel_data: ThreatModelData):
        if self.exclude_as_filter:
            for threat_id in threatmodel_data.threats.copy():
                if threat_id.lower() in self.filter.threats:
                    threatmodel_data.threats.pop(threat_id)
        else:
            for threat_id in threatmodel_data.threats.copy():
                if threat_id.lower() not in self.filter.threats:
                    threatmodel_data.threats.pop(threat_id)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

    def __pop_downstream_dependent_controls(self, controls_to_filter: list, threatmodel_data: ThreatModelData):
        downstream_controls = threatmodel_data.get_downstream_dependent_controls(controls_to_filter)
        for control_id in threatmodel_data.controls.copy():
            if control_id.lower() in controls_to_filter or control_id.lower() in downstream_controls:
                threatmodel_data.controls.pop(control_id)
        self.__filter_orphan_assurance_controls(threatmodel_data)

    def __pop_upstream_dependent_controls(self, controls_to_filter: list, threatmodel_data: ThreatModelData):
        all_control_dependencies = {}
        for control_id in controls_to_filter:
            upstream_controls = threatmodel_data.get_upstream_dependent_controls(control_id)
            for upstream_control_id, upstream_control in upstream_controls.items():
                if upstream_control_id not in all_control_dependencies:
                    all_control_dependencies[upstream_control_id] = upstream_control
        for control_id in threatmodel_data.controls.copy():
            if control_id not in controls_to_filter and control_id not in all_control_dependencies:
                threatmodel_data.controls.pop(control_id)
        self.__filter_orphan_assurance_controls(threatmodel_data)
    
    def __filter_orphan_assurance_controls(self, threatmodel_data: ThreatModelData):
        active_assurance_control_ids = []
        for control_id, control in threatmodel_data.controls.items():
            if not control.get('assured_by'):
                continue
            for assurance_control in control['assured_by'].split(','):
                active_assurance_control_ids.append(assurance_control)
        for control_id, control in threatmodel_data.controls.copy().items():

            # Remove orphan assurance controls
            if control['coso'] == 'Assurance' and control_id not in active_assurance_control_ids:
                threatmodel_data.controls.pop(control_id)
            
            # Remove orphan reference of removed assurance controls
            if control['coso'] != 'Assurance':
                if not control.get('assured_by'):
                    continue
                filtered_ids = [id for id in control['assured_by'].split(',') if id in threatmodel_data.controls]
                threatmodel_data.controls[control_id]['assured_by'] = ','.join(filtered_ids)

    def __filter_by_controls(self, filter_control_ids: list, threatmodel_data: ThreatModelData):
        if self.exclude_as_filter:
            self.__pop_downstream_dependent_controls(filter_control_ids, threatmodel_data)
        else:
            self.__pop_upstream_dependent_controls(filter_control_ids, threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
    
    def __filter_by_control_objectives(self, threatmodel_data: ThreatModelData):
        filter_control_ids = []
        for control_id, control in threatmodel_data.controls.items():
            if control['objective'].lower() in self.filter.control_objectives:
                filter_control_ids.append(control_id)
        self.__filter_by_controls(filter_control_ids, threatmodel_data)
        if self.exclude_as_filter:
            for control_objective_id in threatmodel_data.control_objectives.copy():
                if control_objective_id.lower() in self.filter.control_objectives:
                    threatmodel_data.control_objectives.pop(control_objective_id)
        else:
            for control_objective_id in threatmodel_data.control_objectives.copy():
                if control_objective_id.lower() not in self.filter.control_objectives:
                    threatmodel_data.control_objectives.pop(control_objective_id)
        self.__filter_controls_by_current_control_objectives(threatmodel_data)
from .filter import Filter
from .threatmodel_data import ThreatModelData, get_permissions

SEVERITY_ORDER = ("very high", "high", "medium", "low", "very low")

class FilterApplier:
    def __init__(self, filter: Filter):
        self.filter = filter

    def apply_filter(self, threatmodel_data: ThreatModelData):
        if self.filter.severity:
            self.__filter_by_severity(threatmodel_data=threatmodel_data)
        if self.filter.feature_classes:
            self.__filter_by_feature_class(threatmodel_data=threatmodel_data)
        if self.filter.permissions:
            self.__filter_by_permissions(threatmodel_data=threatmodel_data)
    
    def __filter_by_severity(self, threatmodel_data: ThreatModelData):
        severity_index = SEVERITY_ORDER.index(self.filter.severity)
        allowed_severities = set(severity.lower() for severity in SEVERITY_ORDER[:severity_index + 1])
        for threat_id, threat in threatmodel_data.threats.copy().items():
            if threat.get("cvss_severity", "").lower() not in allowed_severities:
                threatmodel_data.threats.pop(threat_id)
        self.__filter_feature_classes_by_current_threats(threatmodel_data)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

    def __filter_feature_classes_by_current_threats(self, threatmodel_data: ThreatModelData):
        active_fc_ids = threatmodel_data.get_feature_classes_for_current_threats()
        for feature_class_id, _ in threatmodel_data.feature_classes.copy().items():
            if feature_class_id not in active_fc_ids:
                threatmodel_data.feature_classes.pop(feature_class_id)

    def __filter_controls_by_current_threats(self, threatmodel_data: ThreatModelData):
        active_controls = threatmodel_data.get_controls_for_current_threats()
        for control_id, _ in threatmodel_data.controls.copy().items():
            if control_id not in active_controls:
                threatmodel_data.controls.pop(control_id)

    def __filter_control_objectives_by_current_controls(self, threatmodel_data: ThreatModelData):
        active_control_objectives = [value['objective'] for value in threatmodel_data.controls.values()]
        for co_id, _ in threatmodel_data.control_objectives.copy().items():
            if co_id not in active_control_objectives:
                threatmodel_data.control_objectives.pop(co_id)

    def __filter_actions_by_current_feature_classes(self, threatmodel_data: ThreatModelData):
        for action_id, action in threatmodel_data.actions.copy().items():
            if action['feature_class'] not in threatmodel_data.feature_classes:
                threatmodel_data.actions.pop(action_id)
    
    def __filter_by_feature_class(self, threatmodel_data: ThreatModelData):
        feature_class_ids = []
        for filtered_fc in self.filter.feature_classes:
            filtered_fc_ids = threatmodel_data.get_feature_class_hierarchy(filtered_fc)
            for fc_id in filtered_fc_ids:
                if fc_id not in feature_class_ids:
                    feature_class_ids.append(fc_id)
        for fc_id, _ in threatmodel_data.feature_classes.copy().items():
            if fc_id not in feature_class_ids:
                threatmodel_data.feature_classes.pop(fc_id)
        self.__filter_threats_by_feature_classes(threatmodel_data)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

    def __filter_threats_by_feature_classes(self, threatmodel_data: ThreatModelData):
        for threat_id, threat in threatmodel_data.threats.copy().items():
            if threat.get("feature_class") not in threatmodel_data.feature_classes:
                threatmodel_data.threats.pop(threat_id)

    def __filter_by_permissions(self, threatmodel_data: ThreatModelData):
        for threat_id, threat in threatmodel_data.threats.copy().items():
            has_access = False
            permissions = get_permissions(threat.get("access"))
            print(permissions)
            if any([x in self.filter.permissions for x in permissions]):
                has_access = True
            if not has_access:
                threatmodel_data.threats.pop(threat_id)
        self.__filter_feature_classes_by_current_threats(threatmodel_data)
        self.__filter_controls_by_current_threats(threatmodel_data)
        self.__filter_control_objectives_by_current_controls(threatmodel_data)
        self.__filter_actions_by_current_feature_classes(threatmodel_data)

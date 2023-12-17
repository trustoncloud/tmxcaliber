from .filter import Filter
from .threatmodel_data import ThreatModelData

SEVERITY_ORDER = ("Very High", "High", "Medium", "Low", "Very Low")

class FilterApplier:
    def __init__(self, filter: Filter):
        self.filter = filter

    def apply_filter(self, threatmodel_data: ThreatModelData):
        if self.filter.severity:
            severity_index = SEVERITY_ORDER.index(self.filter.severity.capitalize())
            allowed_severities = set(SEVERITY_ORDER[:severity_index + 1])
            for threat_id, threat in threatmodel_data.threats.copy().items():
                if threat.get("cvss_severity", "").capitalize() not in allowed_severities:
                    threatmodel_data.threats.pop(threat_id)

'''
        if args.ids:
            current_prefix = None
            for id in args.ids:
                if not current_prefix:
                    match = re.match(IDS_FORMAT_REGEX, id)
                    current_prefix = match.group(1)
            if current_prefix == "t":
                threats = get_threats(data, args.ids)
                feature_classes = get_feature_classes(data, threats)
                actions = get_actions(data, feature_classes)
                controls = get_controls(data, feature_classes, threats)
                objectives = get_objectives(data, controls)
        else:
            threats: dict = data.get("threats")
            if args.severity:
                for threat_id, threat in threats.copy().items():
                    if threat.get("cvss_severity").lower() != args.severity.lower():
                        threats.pop(threat_id)
            if args.events:
                actions: dict = data.get("actions")
                for _, action in actions.copy().items():
                    if action.get("event_name").lower() in args.events:
                        perms = [
                            x.lower() for x in
                            action.get("iam_permission").split(",")
                        ]
                        filter_by_perms(threats, perms)
            if args.permission:
                filter_by_perms(threats, args.permission)
            if args.feature_class:
                filter_by_fc(threats, args.feature_class)

            feature_classes = get_feature_classes(data, threats)
            actions = get_actions(data, feature_classes)
            controls = get_controls(data, feature_classes)
            objectives = get_objectives(data, controls)

        return {
            "threats": threats,
            "feature_classes": feature_classes,
            "controls": controls,
            "control_objectives": objectives,
            "actions": actions
        }
'''

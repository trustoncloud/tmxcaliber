# Core library functions for tmxcaliber

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

def filter_by_perms(threats: dict, perms: list) -> dict:
    for threat_id, threat in threats.copy().items():
        has_access = False
        permissions = get_permissions(threat.get("access"))
        if any([x in perms for x in permissions]):
            has_access = True
        if not has_access:
            threats.pop(threat_id)

def filter_by_fc(threats: dict, feature_classes: list) -> dict:
    for threat_id, threat in threats.copy().items():
        if threat["feature_class"].lower() not in feature_classes:
            threats.pop(threat_id)

def get_threats(data: dict, ids: list) -> dict:
    threats = {}
    for threat in data.get("threats"):
        if threat.lower() in ids:
            threats[threat] = data.get("threats")[threat]
    return threats

def get_feature_classes(data: dict, threats: dict) -> dict:
    feature_classes = {
        key: value for key, value in data["feature_classes"].items()
        if key in [threat["feature_class"] for threat in threats.values()]
    }
    for feature_class in feature_classes.copy().values():
        for relation in feature_class["class_relationship"]:
            if relation["type"] != "parent":
                continue
            class_name = relation["class"]
            feature_classes[class_name] = data["feature_classes"][class_name]
    return feature_classes

def get_controls(data: dict, feature_classes: dict, threats: dict = {}) -> dict:
    controls = {}
    if threats:
        threat_ids = set(threats.keys())
        for control_id, control in data["controls"].items():
            # Check if the control's feature class is in the list of feature classes
            if any(fc in control["feature_class"] for fc in feature_classes):
                # Check if any mitigation in the control is related to the threats we have
                if any(mitigation.get("threat") in threat_ids for mitigation in control.get("mitigate", [])):
                    controls[control_id] = control
    else:
        # If threats dict is empty, include all controls that match the feature class criteria
        for control_id, control in data["controls"].items():
            if any(fc in control["feature_class"] for fc in feature_classes):
                controls[control_id] = control
    return controls

def get_objectives(data: dict, controls: dict) -> dict:
    objectives = {}
    for name, objective in data["control_objectives"].items():
        for control in controls.values():
            if name == control["objective"]:
                objectives[name] = objective
                break
    return objectives

def get_actions(data: dict, feature_classes: dict) -> dict:
    actions = {}
    for name, action in data["actions"].items():
        for feature_class in feature_classes:
            if feature_class == action["feature_class"]:
                actions[name] = action
                break
    return actions

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
    return control_id_list

def filter_down(args: Namespace, data: dict) -> dict:
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
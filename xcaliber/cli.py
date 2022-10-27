import sys
import json
import pkg_resources
from argparse import Namespace
from argparse import ArgumentParser, RawTextHelpFormatter


def _get_version():
    module_name = vars(sys.modules[__name__])['__package__']
    return f'%(prog)s {pkg_resources.require(module_name)[0].version}'


def get_params():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        "source", type=str,
        help="path to threat model JSON file."
    )
    parser.add_argument(
        '-v', '--version', action='version', version=_get_version(),
        help='show the installed version.\n\n'
    )
    parser.add_argument(
        "--severity", type=str, choices=["high", "medium", "low"],
        help="filter data by threat severity.\n\n"
    )
    parser.add_argument(
        "--perms", nargs="*",
        help="filter data by threat IAM permission(s).\n\n"
    )
    parser.add_argument(
        "--feature-class", nargs="*",
        help="filter data by threat feature class.\n\n"
    )
    parser.add_argument(
        "--events", nargs="*",
        help="filter data by actions log events."
    )

    return validate(parser.parse_args())


def validate(args: Namespace):
    args.severity = args.severity.lower() if args.severity else ""
    args.events = [x.lower() for x in args.events or []]
    args.perms = [x.lower() for x in args.perms or []]
    args.feature_class = [x.lower() for x in args.feature_class or []]
    return args


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


def get_controls(data: dict, feature_classes: dict) -> dict:
    controls = {
        key: value for key, value in data["controls"].items()
        if any([
            feature_class in value["feature_class"]
            for feature_class in feature_classes
        ])
    }
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


def filter_down(args: Namespace, data: dict) -> dict:
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
    if args.perms:
        filter_by_perms(threats, args.perms)
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


def main():
    params = get_params()
    try:
        data = json.load(open(params.source))
        print(json.dumps(filter_down(params, data), indent=2))
    except FileNotFoundError:
        print("File not found:", params.source)
        exit(1)
    except json.JSONDecodeError:
        print("Invalid JSON data for the threat model:", params.source)
        exit(1)

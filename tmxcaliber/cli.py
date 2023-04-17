import sys
import json
import pkg_resources
import re
from argparse import Namespace
from argparse import ArgumentParser, RawTextHelpFormatter

GUARDDUTY_FINDINGS = '(Trojan|UnauthorizedAccess|Discovery|Exfiltration|Impact|PenTest|Policy|Stealth|CredentialAccess|Execution|CryptoCurrency|Backdoor|PrivilegeEscalation|DefenseEvasion|InitialAccess|Persistence|Recon):\w+\/[\w!.-]+'
IDS_INPUT_SEPARATOR = ';'
IDS_FORMAT_REGEX = r'^\w+\.(fc|t|c|co)\d+$'

def _get_version():
    module_name = vars(sys.modules[__name__])['__package__']
    return f'%(prog)s {pkg_resources.require(module_name)[0].version}'

def get_params():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        "operation", type=str, choices=["filter", "map", "scan"],
        help="Operation to apply on the ThreatModel JSON file."
    )
    parser.add_argument(
        "source", type=str,
        help="Path to ThreatModel JSON file."
    )
    parser.add_argument(
        '-v', '--version', action='version', version=_get_version(),
        help='Show the installed version.\n\n'
    )
    if parser.parse_known_args()[0].operation == "filter":
        parser.add_argument(
            "--severity", type=str, choices=["very high", "high", "medium", "low", "very low"],
            help="Filter data by threat severity.\n\n"
        )
        parser.add_argument(
            "--perms", nargs="*",
            help="Filter data by threat IAM permission(s). Separate by spaces, if several.\n\n"
        )
        parser.add_argument(
            "--feature-class", nargs="*",
            help="Filter data by threat feature class. Separate by spaces, if several.\n\n"
        )
        parser.add_argument(
            "--events", nargs="*",
            help="Filter data by actions log events. Separate by spaces, if several.\n\n"
        )

        def validate_id_format(input_ids: str) -> str:
            ids = [x.lower() for x in input_ids.split(IDS_INPUT_SEPARATOR) or []]
            id_prefix = None

            for value in ids:
                match = re.match(IDS_FORMAT_REGEX, value)
                if not match:
                    parser.error(f"Invalid ID format: {value}. Expected format is 'somestring.(FC|T|C|CO)somenumber'")

                current_prefix = match.group(1)
                if id_prefix is None:
                    id_prefix = current_prefix
                elif id_prefix != current_prefix:
                    parser.error("Inconsistent ID types. Please provide IDs with the same prefix (FC|T|C|CO)")
            return input_ids

        parser.add_argument(
            "--ids", nargs="*", type=validate_id_format,
            help=f"Filter data by IDs (only works for threats for now). Separate by {IDS_INPUT_SEPARATOR}, if several.\n\n"
        )
    if parser.parse_known_args()[0].operation == "map":
        parser.add_argument(
            "--scf", type=str, required=True,
            help="Path to the Secure Controls Framework OSCAL JSON data. Available at https://github.com/securecontrolsframework/scf-oscal-catalog-model/tree/main/SCF-OSCAL%20Releases\n\n"
        )
        parser.add_argument(
            "--framework", type=str, required=True,
            help="Framework to map to. It must be the exact name present in the SCF.\n\n"
        )
        parser.add_argument(
            "--format", type=str, required=True, choices=["json", "csv"],
            help="Format to output."
        )

    if parser.parse_known_args()[0].operation == "scan":  # Add this condition for "scan" operation
        parser.add_argument(
            "--pattern", type=str, required=True,
            help="Regex pattern to find in control descriptions.\n\n"
        )

    return validate(parser.parse_args())

def validate(args: Namespace):
    if args.operation == 'filter':
        args.severity = args.severity.lower() if args.severity else ""
        args.events = [x.lower() for x in args.events or []]
        args.perms = [x.lower() for x in args.perms or []]
        args.feature_class = [x.lower() for x in args.feature_class or []]
        if args.ids:
            args.ids = [x.lower() for x in args.ids[0].split(IDS_INPUT_SEPARATOR)]
        else:
            args.ids = []
    if args.operation == 'map':
        args.framework = args.framework.replace('\\n','\n')
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

def get_threats(data: dict, ids: list) -> dict:
    threats = {}
    for threat in data.get('threats'):
        if threat.lower() in ids:
            threats[threat] = data.get('threats')[threat]
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

def get_classified_cvssed_control_ids_by_co(control_id_by_cvss_severity, control_obj_id, control_data):
    severity_range = ('Very High', 'High', 'Medium', 'Low', 'Very Low')
    control_id_list = {}

    for i, severity in enumerate(severity_range):
        if control_id_by_cvss_severity:
            control_id_list[severity] = control_id_by_cvss_severity[severity]
        else:
            control_id_list[severity] = []
        for control in control_data:
            if control_data[control]['objective'] != control_obj_id:
                continue
            if control_data[control]['weighted_priority'] != severity:
                continue
            add_control = True
            if control in control_id_list[severity]:
                add_control = False
            if i > 0:
                for severity_prev in severity_range[0:i]:
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
        if current_prefix == 't':
            threats = get_threats(data, args.ids)
            feature_classes = get_feature_classes(data, threats)
            actions = get_actions(data, feature_classes)
            controls = get_controls(data, feature_classes)
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

def map(args: Namespace, data: dict) -> dict:
    controls: dict = data.get("controls")
    objectives: dict = data.get("control_objectives")
    scf_data: list = json.load(open(args.scf))
    framework: str = args.framework
    framework2scf: dict = {}
    for scf_line in scf_data:
        scf_id = scf_line['SCF #']
        if not framework in scf_line or not scf_line[framework]:
            continue
        for framework_id in scf_line[framework]:
            try:
                framework2scf[framework_id].append(scf_id)
            except KeyError:
                framework2scf[framework_id] = []
                framework2scf[framework_id].append(scf_id)
    scf2co: dict = {}
    for objective in objectives:
        scf_mapping = objectives[objective]['scf'].split(',')
        for scf_id in scf_mapping:
            try:
                scf2co[scf_id].append(objective)
            except KeyError:
                scf2co[scf_id] = []
                scf2co[scf_id].append(objective)
    framework2co: dict = {}
    for control_framework in framework2scf:
        for scf_id in framework2scf[control_framework]:
            if scf_id not in scf2co:
                continue
            try:
                framework2co[control_framework]['control_objectives'].extend(scf2co[scf_id])
            except KeyError:
                framework2co[control_framework] = {}
                framework2co[control_framework]['control_objectives'] = scf2co[scf_id]
    framework2co = dict(sorted(framework2co.items()))

    for control_framework in framework2co:
        control_id_by_cvss_severity = []
        for co_id in framework2co[control_framework]['control_objectives']:
            control_id_by_cvss_severity = get_classified_cvssed_control_ids_by_co(control_id_by_cvss_severity, co_id, controls)
        framework2co[control_framework]['controls'] = control_id_by_cvss_severity
    return framework2co

def scan_controls(args: Namespace, data: dict) -> dict:
    if args.pattern == 'guardduty_findings':
        pattern = re.compile(GUARDDUTY_FINDINGS)
    else:
        pattern = re.compile(args.pattern)
    controls: dict = data.get("controls")
    matched_controls = {}
    
    for control_id, control in controls.items():
        if pattern.search(control.get("description", "")):
            matched_controls[control_id] = control

    return {"controls": matched_controls}

def main():
    params = get_params()
    try:
        data = json.load(open(params.source))
        if params.operation == 'filter':
            print(json.dumps(filter_down(params, data), indent=2))
        if params.operation == 'map':
            map_json = map(params, data)
            if params.format == 'json':
                print(json.dumps(map_json, indent=2))
            if params.format == 'csv':
                csv_line = []
                csv_line.append('Framework,"Control Objectives","Control - Very High","Control - High","Control - Medium","Control - Low","Control - Very Low"')
                for framework_id in map_json:
                    co: str = ",".join(map_json[framework_id]["control_objectives"])
                    c_vh: str = ",".join(map_json[framework_id]["controls"]["Very High"])
                    c_h: str = ",".join(map_json[framework_id]["controls"]["High"])
                    c_m: str = ",".join(map_json[framework_id]["controls"]["Medium"])
                    c_l: str = ",".join(map_json[framework_id]["controls"]["Low"])
                    c_vl: str = ",".join(map_json[framework_id]["controls"]["Very Low"])
                    csv_line.append(f'{framework_id},"{co}","{c_vh}","{c_h}","{c_m}","{c_l}","{c_vl}"')
                output_file = f'output_{params.source.split(".")[0]}.csv'
                with open(output_file, 'w') as csvfile:
                    for service in csv_line[:-1]:
                        csvfile.write(service+'\n')
                    csvfile.write(csv_line[-1])
                print(f'Mapping output in: {output_file}')
        if params.operation == 'scan': 
            print(json.dumps(scan_controls(params, data), indent=2))
    except FileNotFoundError:
        print("File not found:", params.source)
        exit(1)
    except json.JSONDecodeError:
        print("Invalid JSON data for the ThreatModel:", params.source)
        exit(1)

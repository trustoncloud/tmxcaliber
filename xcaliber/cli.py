import json
from argparse import ArgumentParser
from argparse import Namespace


def get_params():
    parser = ArgumentParser()
    parser.add_argument("source", type=str, help="path to threat model JSON file.")

    parser.add_argument(
        "--severity", type=str, choices=["high", "medium", "low"],
        help="filter data by threat severity."
    )
    parser.add_argument(
        "--perms", nargs="*",
        help="filter data by threat IAM permission(s)."
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


def filter_down(args: Namespace, data: dict, display=False) -> dict:
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

    if display:
        print(threats)
    return threats


if __name__ == "__main__":
    params = get_params()
    try:
        data = json.load(open(params.source))
        filter_down(params, data, display=True)
    except FileNotFoundError:
        print("File not found:", params.source)
        exit(1)
    except json.JSONDecodeError:
        print("Invalid JSON data for the threat model:", params.source)
        exit(1)

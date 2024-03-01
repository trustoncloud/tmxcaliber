import re
import os
import io
import csv
import sys
import json
import pandas as pd
from pandas import DataFrame
import platform
import pkg_resources
from typing import Union
from shutil import rmtree
from base64 import b64decode
from argparse import Namespace
from argparse import ArgumentParser
from argparse import ArgumentTypeError
from argparse import RawTextHelpFormatter

from colorama import Fore

from .lib.filter import Filter, IDS_INPUT_SEPARATOR, FEATURE_CLASSES_INPUT_SEPARATOR, EVENTS_INPUT_SEPARATOR, PERMISSIONS_INPUT_SEPARATOR
from .lib.threatmodel_data import ThreatModelData, get_classified_cvssed_control_ids_by_co
from .lib.filter_applier import FilterApplier
from .lib.error import FrameworkNotFoundError
from .lib.cache import get_cached_local_path_for
from .opacity import generate_xml
from .opacity import generate_pngs


GUARDDUTY_FINDINGS = "(" + "|".join([
    "Trojan",
    "UnauthorizedAccess",
    "Discovery",
    "Exfiltration",
    "Impact",
    "PenTest",
    "Policy",
    "Stealth",
    "CredentialAccess",
    "Execution",
    "CryptoCurrency",
    "Backdoor",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "InitialAccess",
    "Persistence",
    "Recon"
]) + ")" + ":\w+\/[\w!.-]+"

CURR_DIR = os.getcwd()
XML_DIR = os.path.join(CURR_DIR, "xmls")
IMG_DIR = os.path.join(CURR_DIR, "img")

class BinaryNotFound(Exception):
    pass

class Operation:
    filter = "filter"
    map = "map"
    scan = "scan"
    generate = "generate"
    list = "list"

class ListOperation:
    threats = "threats"
    controls = "controls"

def _get_version():
    module_name = vars(sys.modules[__name__])["__package__"]
    return f"%(prog)s {pkg_resources.require(module_name)[0].version}"

def is_file(path: str) -> str:
    if not os.path.exists(path):
        raise ArgumentTypeError(f"The path {path} does not exist.")
    if not os.path.isfile(path):
        raise ArgumentTypeError(f"The path {path} is neither a file.")
    if os.path.isfile(path) and not (path.lower().endswith('.json') or path.lower().endswith('.xml')):
        raise ArgumentTypeError(f"The file {path} is not valid, only json or XML can be given.")
    return path

def add_source_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "source", type=is_file, 
            help="Path to the ThreatModel JSON file. We support XML file for internal purposes."
        )

def add_severity_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--severity", type=str, choices=[
                "very high", "high", "medium", "low", "very low"
            ], help="filter data by threat for severity equal or above the selected value.\n\n"
        )

def add_feature_classes_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--feature-classes", type=str, help=(
                "filter data by feature class. "
                f"Separate by `{FEATURE_CLASSES_INPUT_SEPARATOR}`, if several.\n\n"
            )
        )

def add_ids_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--ids", type=str, help=(
                "filter data by IDs (only works for threats for now). "
                f"Separate by `{IDS_INPUT_SEPARATOR}`, if several.\n\n"
            )
        )

def is_file_or_dir(path: str) -> str:
    if not os.path.exists(path):
        raise ArgumentTypeError(f"The path {path} does not exist.")
    if not (os.path.isfile(path) or os.path.isdir(path)):
        raise ArgumentTypeError(f"The path {path} is neither a file nor a directory.")
    if os.path.isfile(path) and not (path.lower().endswith('.json') or path.lower().endswith('.xml')):
        raise ArgumentTypeError(f"The file {path} is not valid, only json or xml can be given.")
    return path

def add_source_json_or_dir_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "source", type=is_file_or_dir,
            help="Path to the ThreatModel JSON file or directory containing ThreatModel JSON files."
        )

def add_csv_output_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--output", type=str, help="Output CSV file to write the results. If not provided, prints to stdout."
        )

def get_params():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        "-v", "--version", action="version", version=_get_version(),
        help="show the installed version.\n\n"
    )

    subparsers = parser.add_subparsers(
        title="operation", dest="operation", required=True
    )
    # subparser for filter operation.
    filter_parser = subparsers.add_parser(
        Operation.filter, help="filter down the ThreatModel data.",
        formatter_class=RawTextHelpFormatter
    )
    filter_parser.add_argument(
        "--permissions", type=str, help=(
            "filter data by IAM permission(s). "
            f"Separate by `{PERMISSIONS_INPUT_SEPARATOR}`, if several.\n\n"
        )
    )
    filter_parser.add_argument(
        "--events", type=str, help=(
            "filter data by actions log events. "
            f"Separate by `{EVENTS_INPUT_SEPARATOR}`, if several.\n\n"
        )
    )

    # subparser for map operation.
    map_parser = subparsers.add_parser(
        Operation.map, help="map ThreatModel data to OSCAL framework.",
        formatter_class=RawTextHelpFormatter
    )
    map_parser.add_argument(
        "--scf", type=str, required=True, choices=["2023.4"], help=(
            "Version of the Secure Control Framework\n\n"
        )
    )
    map_parser.add_argument(
        "--framework", type=str, required=True, help=(
            "framework to map to (must be the "
            "exact name present in the SCF.)\n\n"
        )
    )
    map_parser.add_argument(
        "--format", type=str,
        choices=["json", "csv"], default='csv', help="format to output (default to CSV)."
    )

    # subparser for scan operation.
    scan_parser = subparsers.add_parser(
        Operation.scan, help="scan the ThreatModel data for a given pattern.",
        formatter_class=RawTextHelpFormatter
    )
    scan_parser.add_argument(
        "--pattern", type=str, required=True,
        help="regex pattern to find in control descriptions.\n\n"
    )

    gen_parser = subparsers.add_parser(
        Operation.generate, help="generate threat specific PNGs from XML data.",
        formatter_class=RawTextHelpFormatter
    )
    gen_parser.add_argument(
        "--bin",
        help="path to `drawio` binary. (if not detected automatically)"
    )
    gen_parser.add_argument(
        "--threat-dir",
        default=XML_DIR,
        help="output dir for threat files " \
            f"(.{os.path.join(os.path.sep, os.path.basename(XML_DIR))})"
    )
    gen_parser.add_argument(
        "--fc-dir",
        default=XML_DIR,
        help="output dir for feature class files " \
            f"(.{os.path.join(os.path.sep, os.path.basename(XML_DIR))})"
    )
    gen_parser.add_argument(
        "--validate",
        default=False,
        action="store_true",
        help="flag indicating whether to do validation or not."
    )
    gen_parser.add_argument(
        "--out-dir",
        default=IMG_DIR,
        help="output dir for PNG files " \
            f"(.{os.path.join(os.path.sep, os.path.basename(IMG_DIR))})"
    )

    # subparser for list operation.
    list_parser = subparsers.add_parser(
        Operation.list, help="List data of one or more ThreatModels.",
        formatter_class=RawTextHelpFormatter
    )
    list_subparsers = list_parser.add_subparsers(
        title="list_type", dest="list_type", required=True
    )
    threat_list_parser = list_subparsers.add_parser(
        ListOperation.threats, help="List threat data of one or more ThreatModels.",
        formatter_class=RawTextHelpFormatter
    )
    control_list_parser = list_subparsers.add_parser(
        ListOperation.controls, help="List control data of one or more ThreatModels.",
        formatter_class=RawTextHelpFormatter
    )
    add_source_json_or_dir_argument(threat_list_parser, control_list_parser)
    add_csv_output_argument(threat_list_parser, control_list_parser)
    add_source_argument(filter_parser, map_parser, scan_parser, gen_parser)
    add_severity_filter_argument(threat_list_parser, filter_parser)
    add_feature_classes_filter_argument(threat_list_parser, filter_parser)
    add_ids_filter_argument(filter_parser)
    return validate(parser.parse_args())

def validate_and_get_framework(csv_path: str) -> DataFrame:
    # Read the CSV file into a DataFrame
    df = pd.read_csv(csv_path, header=None)

    # Validate that the DataFrame has exactly 2 columns
    if len(df.columns) != 2:
        raise ValueError(f"The CSV file at {csv_path} should have exactly 2 columns.")

    # Split any cells containing semicolons into multiple rows
    df = (df.set_index(df.columns.drop(1,1).tolist())
          .stack()
          .str.split(';', expand=True)
          .stack()
          .unstack(-2)
          .reset_index(-1, drop=True)
          .reset_index()
    )

    # Remove any duplicate rows
    df = df.drop_duplicates()

    return df

def validate(args: Namespace) -> Namespace:
    if args.operation == Operation.filter:
        args.filter_obj = Filter(severity=args.severity, events=args.events, permissions=args.permissions, feature_classes=args.feature_classes, ids=args.ids)
    if args.operation == Operation.list:
        if args.list_type == ListOperation.threats:
            args.filter_obj = Filter(severity=args.severity, feature_classes=args.feature_classes)
        if args.list_type == ListOperation.controls:
            args.filter_obj = Filter()
    if args.operation == Operation.map:
        args.framework = args.framework.replace("\\n","\n")
    if args.operation == Operation.generate:
        if isinstance(args.source, str) and not args.source.endswith('_DFD.xml') and not args.source.endswith('.json'):
            raise ArgumentTypeError('Only the XML from the main ThreatModel can be used to generate DFD images.')
    return args

def map(args: Namespace, data: dict) -> dict:
    controls: dict = data.get("controls")
    objectives: dict = data.get("control_objectives")
    scf_data: list = json.load(open(args.scf))
    framework: str = args.framework
    framework2scf: dict = {}
    for scf_line in scf_data:
        scf_id = scf_line["SCF #"]
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
        scf_mapping = objectives[objective]["scf"].split(",")
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
                framework2co[control_framework] \
                    ["control_objectives"].extend(scf2co[scf_id])
            except KeyError:
                framework2co[control_framework] = {}
                framework2co[control_framework] \
                    ["control_objectives"] = scf2co[scf_id]
    framework2co = dict(sorted(framework2co.items()))

    for control_framework in framework2co:
        control_id_by_cvss_severity = []
        for co_id in framework2co[control_framework]["control_objectives"]:
            control_id_by_cvss_severity = \
                get_classified_cvssed_control_ids_by_co(
                control_id_by_cvss_severity, co_id, controls
            )
        framework2co[control_framework] \
            ["controls"] = control_id_by_cvss_severity
    return framework2co

def scan_controls(args: Namespace, data: dict) -> dict:
    if args.pattern == "guardduty_findings":
        pattern = re.compile(GUARDDUTY_FINDINGS)
    else:
        pattern = re.compile(args.pattern)
    controls: dict = data.controls
    matched_controls = {}
    
    for control_id, control in controls.items():
        if pattern.search(control.get("description", "")):
            matched_controls[control_id] = control

    return {"controls": matched_controls}

def get_input_data(params: Namespace) -> Union[dict, str, list]:
    is_threatmodel_json = False
    if os.path.isdir(params.source):
        json_file_paths = [os.path.join(params.source, f) for f in os.listdir(params.source) if f.endswith('.json')]
        is_threatmodel_json = True
    elif os.path.isfile(params.source):
        if params.source.endswith('.xml'):
            with open(params.source, 'r') as file:
                return file.read()
        elif params.source.endswith('.json'):
            json_file_paths = [params.source]
            is_threatmodel_json = True
    
    if is_threatmodel_json:
        threatmodel_data_list = []
        if params.operation != 'list' and len(json_file_paths) > 1:
            raise ArgumentTypeError(f'Only 1 file can be given for {params.operation}')
        for json_file_path in json_file_paths:
            try:
                with open(json_file_path) as f:
                    threatmodel_data_list.append(ThreatModelData(json.load(f)))
            except json.JSONDecodeError:
                print(f"Invalid JSON data in file: {json_file_path}")
                exit(1)
            except FileNotFoundError:
                print(f"File not found: {json_file_path}")
                exit(1)
        return threatmodel_data_list

def get_drawio_binary_path():
    if platform.system().lower() == "windows":
        for potential_path in [
            "C:\Program Files\draw.io\draw.io.exe",
            "C:\Program Files (x86)\draw.io\draw.io.exe"
        ]:
            if os.path.isfile(potential_path):
                return potential_path
    elif platform.system().lower() == "linux":
        return "xvfb-run -a drawio"
    elif platform.system().lower() == "darwin":
        for potential_path in [
            "/Applications/draw.io.app/Contents/MacOS/draw.io"
        ]:
            if os.path.isfile(potential_path):
                return potential_path

    raise BinaryNotFound(
        "drawio binary not found automatically.",
        "Use --bin flag to specify path to drawio binary."
    )

def main():

    params = get_params()
    # it's either a list of JSON dict, or a string from XML file.
    data = get_input_data(params)

    if params.operation == Operation.filter:
        threatmodel_data = data[0]
        FilterApplier(params.filter_obj).apply_filter(threatmodel_data)
        print(json.dumps(threatmodel_data.get_json(), indent=2))

    elif params.operation == Operation.scan:
        print(json.dumps(scan_controls(params, data[0]), indent=2))

    elif params.operation == Operation.generate:
        if not params.bin:
            try:
                binary = get_drawio_binary_path()
            except BinaryNotFound as exc:
                print(Fore.RED + "\n".join(exc.args) + Fore.RESET + "\n")
                exit(1)
        else:
            binary = params.bin

        if isinstance(data, str):
            main_xml = data
            filename = os.path.basename(params.source)
            parts = filename.split("_DFD.xml")
            if len(parts) != 2:
                print("Invalid XML filename format. "
                      "Expected format: {provider}_{service}_DFD.xml")
                exit(1)
            provider, service = parts[0].split("_", 1)

        elif isinstance(data, list):
            provider = data[0].threatmodel_json.get("metadata", {}).get("provider")
            service = data[0].threatmodel_json.get("metadata", {}).get("service")
            if not (provider and service):
                print("No `provider` or `service` in the JSON data.")
                exit(1)

            body = data[0].threatmodel_json.get("dfd", {}).get("body")
            if not body:
                print("Could not get `dfd.body` from the JSON data.")
                exit(1)

            try:
                main_xml = b64decode(body).decode("utf8")
            except ValueError:
                print("Invalid XML data provided in the JSON.")
                exit(1)

        # remove directories if present already (cleans up old content.)
        if os.path.isdir(XML_DIR):
            rmtree(XML_DIR)
        if os.path.isdir(IMG_DIR):
            rmtree(IMG_DIR)

        prefix = f"{provider}_{service}".upper()
        generate_xml(
            main_xml, prefix, params.threat_dir,
            params.fc_dir, params.validate
        )

        if params.fc_dir != params.threat_dir:
            generate_pngs(binary, params.fc_dir, params.out_dir, 1500)
            generate_pngs(binary, params.threat_dir, params.out_dir, 1500)
        else:
            generate_pngs(binary, params.fc_dir, params.out_dir, 1500)
    
    elif params.operation == Operation.list:
        for threatmodel_data in ThreatModelData.threatmodel_data_list:
            FilterApplier(params.filter_obj).apply_filter(threatmodel_data)
        if params.list_type == ListOperation.threats:
            csv_output = ThreatModelData.get_csv_of_threats()
        if params.list_type == ListOperation.controls:
            csv_output = ThreatModelData.get_csv_of_controls()

        if params.output:
            with open(params.output, 'w+', newline='') as file:
                file.write(csv_output)
        else:
            print(csv_output)

    elif params.operation == Operation.map:
        if params.scf == '2023.4':
            file_location = 'https://github.com/securecontrolsframework/securecontrolsframework/raw/d1428c74aa76a66d9e131e6a3e3d1e61af25bd3a/Secure%20Controls%20Framework%20(SCF)%20-%202023.4.xlsx'
        local_scf = get_cached_local_path_for(file_location)
        # Read the Excel file
        xls = pd.ExcelFile(local_scf)
        # Get the data from the "SCF 2023.4" worksheet
        scf_data = pd.read_excel(xls, 'SCF 2023.4')
        # Check if params.framework is in the columns of the scf_data DataFrame
        if not params.framework.endswith('.csv'):
            # Keep only the columns "SCF #" and the one matching params.framework
            scf_data = scf_data[["SCF #", params.framework]]

        elif params.framework.endswith('.csv'):
            framework_pd = validate_and_get_framework(params.framework)
            print(framework_pd)


        '''
        params.framework = params.framework.replace("\\n","\n")
        map_json = map(params, data, scf_data)
        if params.format == "json":
            print(json.dumps(map_json, indent=2))
        if params.format == "csv":
            csv_line = []
            csv_line.append(",".join([
                "Framework",
                '"Control Objectives"',
                '"Control - Very High"',
                '"Control - High"',
                '"Control - Medium"',
                '"Control - Low"',
                '"Control - Very Low"'
            ]))

            for framework_id in map_json:
                co: str = ",".join(map_json[framework_id]["control_objectives"])
                c_vh: str = ",".join(
                    map_json[framework_id]["controls"]["Very High"]
                )
                c_h: str = ",".join(map_json[framework_id]["controls"]["High"])
                c_m: str = ",".join(
                    map_json[framework_id]["controls"]["Medium"]
                )
                c_l: str = ",".join(map_json[framework_id]["controls"]["Low"])
                c_vl: str = ",".join(
                    map_json[framework_id]["controls"]["Very Low"]
                )
                csv_line.append(",".join([
                    framework_id,
                    f"{co}",
                    f"{c_vh}",
                    f"{c_h}",
                    f"{c_m}",
                    f"{c_l}",
                    f"{c_vl}"
                ]))

            output_file = f'output_{params.source.split(".")[0]}.csv'
            with open(output_file, "w") as csvfile:
                for service in csv_line[:-1]:
                    csvfile.write(service + "\n")
                csvfile.write(csv_line[-1])
            print(f"Mapping output in: {output_file}")
        '''

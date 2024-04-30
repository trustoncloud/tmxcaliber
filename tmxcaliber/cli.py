import re
import os
import sys
import json
import pandas as pd
import csv
from pandas import DataFrame
from itertools import product
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
from .lib.scf import get_scf_data
from .lib.tools import sort_by_id
from .opacity import generate_xml
from .opacity import generate_pngs
from . import parsers

GUARDDUTY_PATTERN_NAME = 'guardduty_findings'
GUARDDUTY_FINDINGS = r"(" + "|".join([
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
]) + r")" + r":\w+\/[\w!.-]+"

CURR_DIR = os.getcwd()
XML_DIR = os.path.join(CURR_DIR, "xmls")
IMG_DIR = os.path.join(CURR_DIR, "img")

METADATA_MISSING = 'Not available in framework-metadata file'

class BinaryNotFound(Exception):
    pass

class Operation:
    filter = "filter"
    map = "map"
    scan = "scan"
    generate = "generate"
    list = "list"
    add_mapping = "add-mapping"

class ListOperation:
    threats = "threats"
    controls = "controls"

def _get_version():
    module_name = vars(sys.modules[__name__])["__package__"]
    return f"{module_name} {pkg_resources.require(module_name)[0].version}"

def add_severity_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--severity", type=str, choices=[
                "very high", "high", "medium", "low", "very low"
            ], help="filter data by threat for severity equal or above the selected value.\n\n"
        )

def add_ids_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--ids", type=str, help=(
                "filter data by IDs (can be feature classes, threats, controls, or control objectives). "
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

def add_exclude_flag(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            '--exclude', action='store_true', help='Enable exclusion mode. Items specified will be excluded from the output.'
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

    filter_parser.add_argument('--output-excluded', action='store_true', help='flag to output all the filtered information into another file. Require --output.')
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

    # subparser for add mapping operation.
    add_mapping_parser = subparsers.add_parser(
        Operation.add_mapping, help="add a supported framework in the Secure Control Framework (https://securecontrolsframework.com) into the ThreatModel JSON data.",
        formatter_class=RawTextHelpFormatter
    )
    parsers.add_scf_argument(add_mapping_parser)
    parsers.add_framework_argument(add_mapping_parser)
    parsers.add_metadata_argument(add_mapping_parser)
    parsers.add_source_argument(add_mapping_parser)

    # subparser for map operation.
    map_parser = subparsers.add_parser(
        Operation.map, help="map ThreatModel data to a supported framework in the Secure Control Framework (https://securecontrolsframework.com).",
        formatter_class=RawTextHelpFormatter
    )
    parsers.add_scf_argument(map_parser)
    parsers.add_framework_argument(map_parser)
    parsers.add_metadata_argument(map_parser)

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
        help= ("regex pattern to find in control descriptions.\n"
            f"For GuardDuty findings, use the pattern: {GUARDDUTY_PATTERN_NAME}\n\n")
    )

    gen_parser = subparsers.add_parser(
        Operation.generate, help="generate threat specific PNGs from XML data.",
        formatter_class=RawTextHelpFormatter
    )
    gen_parser.add_argument(
        "--bin",
        help="path to `drawio` binary (if not detected automatically)"
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
    parsers.add_output_argument(threat_list_parser, control_list_parser, map_parser, add_mapping_parser, filter_parser, scan_parser)
    add_exclude_flag(filter_parser, threat_list_parser, control_list_parser)
    parsers.add_source_argument(filter_parser, map_parser, scan_parser, gen_parser)
    add_severity_filter_argument(threat_list_parser, filter_parser)
    add_ids_filter_argument(filter_parser, threat_list_parser, control_list_parser)
    return validate(parser)

def get_metadata(csv_path: str) -> tuple:
    """
    Reads a CSV file and returns a tuple containing a list of field names beyond the first field and a dictionary where the first column values are the main keys.
    Each key contains a dictionary where the other column headers are the keys.

    Parameters:
    csv_path (str): The path to the CSV file.

    Returns:
    tuple: A tuple where the first element is a list of fields beyond the first one, and the second element is a dictionary representation of the CSV data.
    """
    result = {}
    fields_beyond_id = []

    with open(csv_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)  # Using DictReader to automatically use the header row as keys

        # Capture field names beyond the first one
        fields_beyond_id = reader.fieldnames[1:]

        # Process each row in the CSV
        for row in reader:
            main_key = row.pop(reader.fieldnames[0])  # Remove and get the value of the first column for use as the main key

            # Check if the main key already exists in the dictionary
            if main_key in result:
                # If the key already exists, update the existing dictionary with new values (if necessary)
                for key, value in row.items():
                    if key not in result[main_key]:
                        result[main_key][key] = value
                    else:
                        # Handle potential duplicates or conflicts here, if needed
                        pass
            else:
                # Add the new key and dictionary to the result
                result[main_key] = row

    return fields_beyond_id, result

def validate_and_get_framework(csv_path: str, framework_name: str) -> DataFrame:
    # Read the CSV file into a DataFrame
    df = pd.read_csv(csv_path, header=None)
    # Validate that the DataFrame has exactly 2 columns
    if len(df.columns) != 2:
        raise ValueError(f"The CSV file at {csv_path} should have exactly 2 columns. The SCF on the first, and your framework in the second.")

        # Function to expand the rows based on semicolon-separated entries
    def expand_rows(row):
        col0_parts = str(row[0]).split(';')
        col1_parts = str(row[1]).split(';')
        # Generate all combinations of splits from both columns
        return pd.DataFrame(product(col0_parts, col1_parts), columns=[0, 1])

    # Apply the function and concatenate the results
    df_expanded = pd.concat([expand_rows(row) for index, row in df.iterrows()], ignore_index=True)

    # Remove any duplicate rows
    df_expanded = df_expanded.drop_duplicates()
    df_expanded.columns = ['SCF', framework_name]

    return df_expanded

def validate(parser: ArgumentParser) -> Namespace:
    args = parser.parse_args()
    if args.operation == Operation.filter:
        if args.output_excluded and not args.output:
            parser.error("The '--output-excluded' flag requires '--output' to be specified.")
        args.filter_obj = Filter(
            severity=args.severity,
            events=getattr(args, 'events', ''),
            permissions=getattr(args, 'permissions', ''),
            ids=getattr(args, 'ids', '')
        )
    if args.operation == Operation.list:
        if args.list_type == ListOperation.threats:
            args.filter_obj = Filter(severity=args.severity, ids=args.ids)
        if args.list_type == ListOperation.controls:
            args.filter_obj = Filter(ids=args.ids)
    if args.operation == Operation.generate:
        if isinstance(args.source, str) and not args.source.endswith('_DFD.xml') and not args.source.endswith('.json'):
            parser.error('Only the XML from the main ThreatModel can be used to generate DFD images.')
    return args

def map(framework2co: pd.DataFrame, threatmodel_data: dict, framework_name: str, metadata_fields: list = [], metadata: dict = {}) -> dict:
    controls, objectives = threatmodel_data.controls, threatmodel_data.control_objectives
    # Step 1: Create a list of tuples from the data dictionary
    entries = []
    for top_key, values in objectives.items():
        scf_codes = values['scf']
        for scf_code in scf_codes:
            entries.append((scf_code, top_key))
    # Step 2: Create the DataFrame
    scf2co = pd.DataFrame(entries, columns=['SCF', 'CO'])
    merged_df = pd.merge(scf2co, framework2co, on='SCF', how='left')

    # Group SCFs and COs by framework and collect into lists
    framework_group = merged_df.groupby(framework_name).agg({
        'CO': lambda x: list(x.dropna()),  # Collect COs, dropping NaN values
        'SCF': lambda x: list(x.dropna())  # Collect SCFs, dropping NaN values
    }).dropna().to_dict('index')

    # Prepare the new structure with SCFs included
    framework2co = {}
    for framework, data in framework_group.items():
        framework2co[framework] = {
            'control_objectives': sort_by_id(list(set(data['CO']))),
            'scf': sorted(list(set(data['SCF'])))
        }

        # Your existing logic to classify controls by severity
        control_id_by_cvss_severity = []
        for co_id in framework2co[framework]["control_objectives"]:
            control_id_by_cvss_severity = get_classified_cvssed_control_ids_by_co(
                control_id_by_cvss_severity, co_id, controls
            )
        framework2co[framework]["controls"] = control_id_by_cvss_severity

    if metadata:
        for metadata_id, values in framework2co.items():
            if metadata_id in metadata:
                # If the key exists in metadata, merge the metadata values
                if isinstance(values, dict):
                    # Merge metadata into the existing dictionary for the key in framework2co
                    values.update(metadata[metadata_id])
                else:
                    # Handle cases where the expected structure is not met
                    print(f"Error: Expected a dictionary at framework2co['{metadata_id}'], but found {type(values)}.")
            else:
                for metadata_field in metadata_fields:
                    framework2co[metadata_id][metadata_field] = METADATA_MISSING

    return framework2co

def scan_controls(args: Namespace, data: dict) -> dict:
    if args.pattern == GUARDDUTY_PATTERN_NAME:
        pattern = re.compile(GUARDDUTY_FINDINGS)
    else:
        pattern = re.compile(args.pattern)
    controls: dict = data['controls']
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
    else:
        print(f"File or directory not found: {params.source}")
        exit(1)

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
            r"C:\Program Files\draw.io\draw.io.exe",
            r"C:\Program Files (x86)\draw.io\draw.io.exe"
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

def output_result(output_param, result, result_type, output_excluded_json: dict = {}):
    is_json = False
    is_csv = False
    if result_type == 'json':
        json_result = json.dumps(result, indent=2)
        if output_excluded_json:
            output_excluded_result = json.dumps(output_excluded_json, indent=2)
        is_json = True
    elif result_type == 'csv_list':
        csv_result = result
        is_csv = True
    else:
        raise TypeError('Invalid output result type')

    if output_param:
        if is_json:
            with open(output_param, 'w+', newline='') as file:
                file.write(json_result)
            if output_excluded_json:
                if '.' in output_param:
                    exclude_file_name = '.'.join(output_param.split('.')[:-1]) + '_excluded.' + output_param.split('.')[-1]
                else:
                    exclude_file_name = output_param + '_excluded'
                with open(exclude_file_name, 'w+', newline='') as file:
                    file.write(output_excluded_result)
        elif is_csv:
            with open(output_param, mode='w', newline='', encoding='utf-8') as file:
                csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                for line in csv_result:
                    csv_writer.writerow(line)
    elif is_json:
        print(json_result)
    elif is_csv:
        writer = csv.writer(sys.stdout, quoting=csv.QUOTE_MINIMAL)
        for row in csv_result:
            writer.writerow(row)

def main():

    params = get_params()
    # it's either a list of JSON dict, or a string from XML file.
    data = get_input_data(params)

    if params.operation == Operation.filter:
        threatmodel_data = data[0]
        FilterApplier(params.filter_obj, params.exclude).apply_filter(threatmodel_data)
        excluded_json = {}
        if params.output_excluded:
            excluded_json = threatmodel_data.get_excluded_output()
        output_result(params.output, threatmodel_data.get_json(), 'json', output_excluded_json=excluded_json)

    elif params.operation == Operation.scan:
        output_result(params.output, scan_controls(params, data[0].get_json()), 'json')

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
            FilterApplier(params.filter_obj, params.exclude).apply_filter(threatmodel_data)
        if params.list_type == ListOperation.threats:
            csv_output = ThreatModelData.get_csv_of_threats()
        if params.list_type == ListOperation.controls:
            csv_output = ThreatModelData.get_csv_of_controls()

        output_result(params.output, csv_output, 'csv_list')

    elif params.operation == Operation.map:
        # If SCF-supported framework, we need the data; otherwise we can map directly.
        if not params.framework_map:
            scf_data = get_scf_data(params.scf, framework_name=params.framework_name)
        else:
            scf_data = validate_and_get_framework(params.framework_map, framework_name=params.framework_name)

        metadata = {}
        metadata_fields = []
        if params.framework_metadata:
            metadata_fields, metadata = get_metadata(params.framework_metadata)
        map_json = map(scf_data, data[0], params.framework_name, metadata_fields=metadata_fields, metadata=metadata)
        if params.format == "json":
            output_result(params.output, map_json, 'json')
        if params.format == "csv":
            # Define the fixed titles for your CSV
            titles = [
                params.framework_name,
                "SCF",
                "Control Objectives",
                "Control - Very High",
                "Control - High",
                "Control - Medium",
                "Control - Low",
                "Control - Very Low"
            ]

            # Append the header row first
            csv_lines = []
            csv_lines.append(titles + list(metadata_fields))

            # Iterate through each entry in the map_json to populate the CSV rows
            for framework_id, details in map_json.items():
                # Extract control objectives and control levels with safe defaults if missing
                scf = ";".join(details.get("scf", []))
                co = ";".join(details.get("control_objectives", []))
                controls = details.get("controls", {})
                c_vh = ";".join(controls.get("Very High", []))
                c_h = ";".join(controls.get("High", []))
                c_m = ";".join(controls.get("Medium", []))
                c_l = ";".join(controls.get("Low", []))
                c_vl = ";".join(controls.get("Very Low", []))

                # Start building the row with fixed structure data
                csv_line = [
                    framework_id,
                    scf,
                    co,
                    c_vh,
                    c_h,
                    c_m,
                    c_l,
                    c_vl
                ]

                # Append metadata values, using a safe default if a key is missing
                csv_line.extend(details.get(key, '') for key in metadata_fields)
                csv_lines.append(csv_line)

            output_result(params.output, csv_lines, 'csv_list')

    elif params.operation == Operation.add_mapping:
        # If SCF-supported framework, we need the data; otherwise we can map directly.
        if not params.framework_map:
            scf_data = get_scf_data(params.scf, framework_name=params.framework_name)
        else:
            scf_data = validate_and_get_framework(params.framework_map, framework_name=params.framework_name)

        metadata = {}
        metadata_fields = []
        if params.framework_metadata:
            metadata_fields, metadata = get_metadata(params.framework_metadata)

        threatmodel_data = data[0]
        map_json = map(scf_data, threatmodel_data, params.framework_name, metadata_fields=metadata_fields, metadata=metadata)

        threatmodel_data.threatmodel_json["mapping"] = {}
        for key in sorted(map_json.keys()):
            # Extract everything except the 'controls' subkey
            new_entry = {k: v for k, v in map_json[key].items() if k != 'controls'}
            threatmodel_data.threatmodel_json["mapping"][key] = new_entry

        for co in threatmodel_data.control_objectives:
            framework_controls = []
            for fw_control in map_json:
                if co in map_json[fw_control].get('control_objectives'):
                    framework_controls.append(fw_control)
            threatmodel_data.threatmodel_json["control_objectives"][co][params.framework_name] = sorted(list(set(framework_controls)))

        output_result(params.output, threatmodel_data.threatmodel_json, 'json')
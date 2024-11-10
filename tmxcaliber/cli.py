import re
import os
import sys
import json
import pandas as pd
import csv
from pandas import DataFrame
from itertools import product
import platform
from importlib import metadata
from typing import Union, List
from shutil import rmtree
from base64 import b64decode
from argparse import Namespace
from argparse import ArgumentParser
from argparse import ArgumentTypeError
from argparse import RawTextHelpFormatter

from colorama import Fore

from .lib.filter import Filter
from .lib.threatmodel_data import (
    ThreatModelData,
    get_classified_cvssed_control_ids_by_co,
)
from .lib.filter_applier import FilterApplier
from .lib.change_log import generate_change_log
from .lib.errors import FeatureClassCycleError, BinaryNotFound
from .lib.scf import get_scf_data
from .lib.tools import sort_by_id
from .opacity import generate_xml
from .opacity import generate_pngs
from . import parsers
from .params import (
    Operation,
    ListOperation,
    GUARDDUTY_PATTERN_NAME,
    XML_DIR,
    IMG_DIR,
    GUARDDUTY_FINDINGS,
    METADATA_MISSING,
    MISSING_OUTPUT_ERROR,
)


def _get_version():
    module_name = vars(sys.modules[__name__])["__package__"]
    try:
        version = metadata.version(module_name)
        return f"{module_name} {version}"
    except metadata.PackageNotFoundError:
        return f"{module_name} version not found"


def get_params():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=_get_version(),
        help="show the installed version.\n\n",
    )
    subparsers = parser.add_subparsers(
        title="operation", dest="operation", required=True
    )
    parsers.add_filter_parser(subparsers)
    parsers.add_add_mapping_parser(subparsers)
    parsers.add_map_parser(subparsers)
    parsers.add_scan_parser(subparsers)
    parsers.add_gen_parser(subparsers)
    parsers.add_list_parser(subparsers)
    parsers.add_changelog_parser(subparsers)

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

    with open(csv_path, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(
            file
        )  # Using DictReader to automatically use the header row as keys

        # Capture field names beyond the first one
        fields_beyond_id = reader.fieldnames[1:]

        # Process each row in the CSV
        for row in reader:
            main_key = row.pop(
                reader.fieldnames[0]
            )  # Remove and get the value of the first column for use as the main key

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
    df = df.replace({None: pd.NA})
    df = df.replace({float("nan"): pd.NA})
    df = df.dropna()

    # Validate that the DataFrame has exactly 2 columns
    if len(df.columns) != 2:
        raise ValueError(
            f"The CSV file at {csv_path} should have exactly 2 columns. The SCF on the first, and your framework in the second."
        )

    # Function to expand the rows based on semicolon-separated entries
    def expand_rows(row):
        col0_parts = str(row[0]).split(";")
        col1_parts = str(row[1]).split(";")

        # Filter out empty strings from both columns
        col0_parts = [part for part in col0_parts if part.strip()]
        col1_parts = [part for part in col1_parts if part.strip()]

        # If either side is empty after filtering, return an empty DataFrame
        if not col0_parts or not col1_parts:
            return pd.DataFrame(columns=[0, 1])

        # Generate all combinations of splits from both columns
        return pd.DataFrame(product(col0_parts, col1_parts), columns=[0, 1])

    # Apply the function and concatenate the results
    df_expanded = pd.concat(
        [expand_rows(row) for index, row in df.iterrows()], ignore_index=True
    )

    # Remove any duplicate rows
    df_expanded = df_expanded.drop_duplicates()
    df_expanded.columns = ["SCF", framework_name]
    return df_expanded


def validate(parser: ArgumentParser) -> Namespace:
    args = parser.parse_args()
    if args.operation == Operation.create_change_log:
        args.filter_obj = Filter(ids=args.ids)
    elif args.operation == Operation.filter:
        if args.output_removed and not args.output:
            parser.error(MISSING_OUTPUT_ERROR)
        args.filter_obj = Filter(
            severity=getattr(args, "severity", ""),
            events=getattr(args, "events", ""),
            permissions=getattr(args, "permissions", ""),
            ids=getattr(args, "ids", ""),
        )
    elif args.operation == Operation.generate:
        if (
            isinstance(args.source, str)
            and not args.source.endswith("_DFD.xml")
            and not args.source.endswith(".json")
        ):
            parser.error(
                "Only the XML from the main ThreatModel can be used to generate DFD images."
            )
    elif args.operation == Operation.list:
        if args.list_type == ListOperation.threats:
            args.filter_obj = Filter(severity=args.severity, ids=args.ids)
        if args.list_type == ListOperation.controls:
            args.filter_obj = Filter(ids=args.ids)
    return args


def map(
    framework2co: pd.DataFrame,
    threatmodel_data: dict,
    framework_name: str,
    metadata_fields: list = [],
    metadata: dict = {},
) -> dict:
    controls, objectives = (
        threatmodel_data.controls,
        threatmodel_data.control_objectives,
    )
    # Step 1: Create a list of tuples from the data dictionary
    entries = []
    for top_key, values in objectives.items():
        scf_codes = values["scf"]
        for scf_code in scf_codes:
            entries.append((scf_code, top_key))
    # Step 2: Create the DataFrame
    scf2co = pd.DataFrame(entries, columns=["SCF", "CO"])
    merged_df = pd.merge(scf2co, framework2co, on="SCF", how="left")

    # Group SCFs and COs by framework and collect into lists
    framework_group = (
        merged_df.groupby(framework_name)
        .agg(
            {
                "CO": lambda x: list(x.dropna()),  # Collect COs, dropping NaN values
                "SCF": lambda x: list(x.dropna()),  # Collect SCFs, dropping NaN values
            }
        )
        .dropna()
        .to_dict("index")
    )

    # Prepare the new structure with SCFs included
    framework2co = {}
    for framework, data in framework_group.items():
        framework2co[framework] = {
            "control_objectives": sort_by_id(list(set(data["CO"]))),
            "scf": sorted(list(set(data["SCF"]))),
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
                    print(
                        f"Error: Expected a dictionary at framework2co['{metadata_id}'], but found {type(values)}."
                    )
            else:
                for metadata_field in metadata_fields:
                    framework2co[metadata_id][metadata_field] = METADATA_MISSING

    return framework2co


def scan_controls(args: Namespace, data: dict) -> dict:
    if args.pattern == GUARDDUTY_PATTERN_NAME:
        pattern = re.compile(GUARDDUTY_FINDINGS)
    else:
        pattern = re.compile(args.pattern)
    controls: dict = data["controls"]
    matched_controls = {}

    for control_id, control in controls.items():
        if pattern.search(control.get("description", "")):
            matched_controls[control_id] = control

    return {"controls": matched_controls}


def repair_json_strings(input_str):
    # In case the URL are replaced poorly by an email gateway.
    pattern = re.compile(r"(href=\\\"[^\"]*)")

    def replace_angle(match):
        return f"{match.group(1)}\\"

    repaired_str = pattern.sub(replace_angle, input_str)
    parsed_json = json.loads(repaired_str)
    return parsed_json


def get_file_paths(source: str) -> List[str]:
    if os.path.isdir(source):
        return [
            os.path.join(source, f) for f in os.listdir(source) if f.endswith(".json")
        ]
    elif os.path.isfile(source):
        if source.endswith(".json"):
            return [source]
    return []


def load_json_files(json_file_paths: List[str]) -> List[ThreatModelData]:
    threatmodel_data_list = []
    for json_file_path in json_file_paths:
        try:
            with open(json_file_path, "r") as f:
                file_content = f.read()
                try:
                    data = json.loads(file_content)
                    threatmodel_data_list.append(ThreatModelData(data))
                except json.JSONDecodeError:
                    print(
                        f"Invalid JSON data in file: {json_file_path}. Trying to repair..."
                    )
                    try:
                        data = repair_json_strings(file_content)
                        threatmodel_data_list.append(ThreatModelData(data))
                        print("Repair successful!")
                    except json.JSONDecodeError:
                        print("Repair failed. Exiting.")
                        exit(1)
        except FileNotFoundError:
            print(f"File not found: {json_file_path}")
            exit(1)
    return threatmodel_data_list


def get_input_data(params: Namespace) -> Union[dict, str, List[ThreatModelData]]:

    all_sources = {}
    if hasattr(params, "source") and params.source:
        all_sources["source"] = params.source

    if hasattr(params, "new_source") and params.new_source:
        all_sources["new_source"] = params.new_source

    if hasattr(params, "old_source") and params.old_source:
        all_sources["old_source"] = params.old_source

    all_data = {}
    for key, source in all_sources.items():
        if not os.path.exists(source):
            print(f"File or directory not found: {source}")
            exit(1)

        json_file_paths = get_file_paths(source)

        if params.operation != "list" and len(json_file_paths) > 1:
            raise ArgumentTypeError(f"Only 1 file can be given for {params.operation}")

        if json_file_paths:
            all_data[key] = load_json_files(json_file_paths)
        else:
            if source.endswith(".xml"):
                with open(source, "r") as file:
                    all_data[key] = file.read()
            else:
                print(f"Invalid file type for {source}")
                exit(1)

    if "source" in all_data:
        return all_data["source"]
    else:
        return all_data


def get_drawio_binary_path():
    if platform.system().lower() == "windows":
        for potential_path in [
            r"C:\Program Files\draw.io\draw.io.exe",
            r"C:\Program Files (x86)\draw.io\draw.io.exe",
        ]:
            if os.path.isfile(potential_path):
                return potential_path
    elif platform.system().lower() == "linux":
        return "xvfb-run -a drawio"
    elif platform.system().lower() == "darwin":
        for potential_path in ["/Applications/draw.io.app/Contents/MacOS/draw.io"]:
            if os.path.isfile(potential_path):
                return potential_path

    raise BinaryNotFound(
        "drawio binary not found automatically. Use --bin flag to specify path to drawio binary."
    )


def output_result(output_param, result, result_type, output_removed_json: dict = {}):
    is_json = False
    is_csv = False
    is_md = False
    if result_type == "json":
        json_result = json.dumps(result, indent=2)
        if output_removed_json:
            output_removed_result = json.dumps(output_removed_json, indent=2)
        is_json = True
    elif result_type == "csv_list":
        csv_result = result
        is_csv = True
    elif result_type == "md":
        markdown = result
        is_md = True
    else:
        raise TypeError("Invalid output result type")

    if output_param:
        if is_json:
            with open(output_param, "w+", newline="") as file:
                file.write(json_result)
            if output_removed_json:
                if "." in output_param:
                    exclude_file_name = (
                        ".".join(output_param.split(".")[:-1])
                        + "_removed."
                        + output_param.split(".")[-1]
                    )
                else:
                    exclude_file_name = output_param + "_removed"
                with open(exclude_file_name, "w+", newline="") as file:
                    file.write(output_removed_result)
        elif is_csv:
            with open(output_param, mode="w", newline="", encoding="utf-8") as file:
                csv_writer = csv.writer(
                    file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
                )
                for line in csv_result:
                    csv_writer.writerow(line)
        elif is_md:
            with open(output_param, "w") as md_file:
                md_file.write(markdown)
    elif is_json:
        print(json_result)
    elif is_csv:
        writer = csv.writer(sys.stdout, quoting=csv.QUOTE_MINIMAL)
        for row in csv_result:
            writer.writerow(row)
    elif is_md:
        print(markdown)


def main():

    params = get_params()
    try:
        data = get_input_data(params)
    except FeatureClassCycleError as e:
        raise SystemExit(e)

    if params.operation == Operation.add_mapping:
        # If SCF-supported framework, we need the data; otherwise we can map directly.
        if not params.framework_map:
            scf_data = get_scf_data(params.scf, framework_name=params.framework_name)
        else:
            scf_data = validate_and_get_framework(
                params.framework_map, framework_name=params.framework_name
            )

        metadata = {}
        metadata_fields = []
        if params.framework_metadata:
            metadata_fields, metadata = get_metadata(params.framework_metadata)

        threatmodel_data = data[0]
        map_json = map(
            scf_data,
            threatmodel_data,
            params.framework_name,
            metadata_fields=metadata_fields,
            metadata=metadata,
        )

        threatmodel_data.threatmodel_json["mapping"] = {}
        for key in sorted(map_json.keys()):
            # Extract everything except the 'controls' subkey
            new_entry = {k: v for k, v in map_json[key].items() if k != "controls"}
            threatmodel_data.threatmodel_json["mapping"][key] = new_entry

        for co in threatmodel_data.control_objectives:
            framework_controls = []
            for fw_control in map_json:
                if co in map_json[fw_control].get("control_objectives"):
                    framework_controls.append(fw_control)
            threatmodel_data.threatmodel_json["control_objectives"][co][
                params.framework_name
            ] = sorted(list(set(framework_controls)))

        output_result(params.output, threatmodel_data.threatmodel_json, "json")

    elif params.operation == Operation.create_change_log:
        old_tm_data = data["old_source"][0]
        FilterApplier(params.filter_obj, params.exclude).apply_filter(old_tm_data)
        new_tm_data = data["new_source"][0]
        FilterApplier(params.filter_obj, params.exclude).apply_filter(new_tm_data)
        change_log = generate_change_log(old_tm_data.get_json(), new_tm_data.get_json())
        if params.format == "json":
            output_result(params.output, change_log.get_json(), "json")
        elif params.format == "md":
            output_result(params.output, change_log.get_md(), "md")

    elif params.operation == Operation.filter:
        threatmodel_data = data[0]
        FilterApplier(params.filter_obj, params.exclude).apply_filter(threatmodel_data)
        removed_json = {}
        if params.output_removed:
            removed_json = threatmodel_data.get_removed_output()
        output_result(
            params.output,
            threatmodel_data.get_json(),
            "json",
            output_removed_json=removed_json,
        )

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
                print(
                    "Invalid XML filename format. "
                    "Expected format: {provider}_{service}_DFD.xml"
                )
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
            main_xml, prefix, params.threat_dir, params.fc_dir, params.validate
        )

        if params.fc_dir != params.threat_dir:
            generate_pngs(binary, params.fc_dir, params.out_dir, 1500)
            generate_pngs(binary, params.threat_dir, params.out_dir, 1500)
        else:
            generate_pngs(binary, params.fc_dir, params.out_dir, 1500)

    elif params.operation == Operation.list:
        for threatmodel_data in ThreatModelData.threatmodel_data_list:
            FilterApplier(params.filter_obj, params.exclude).apply_filter(
                threatmodel_data
            )
        if params.list_type == ListOperation.threats:
            csv_output = ThreatModelData.get_csv_of_threats()
        if params.list_type == ListOperation.controls:
            csv_output = ThreatModelData.get_csv_of_controls()

        output_result(params.output, csv_output, "csv_list")

    elif params.operation == Operation.map:
        # If SCF-supported framework, we need the data; otherwise we can map directly.
        if not params.framework_map:
            scf_data = get_scf_data(params.scf, framework_name=params.framework_name)
        else:
            scf_data = validate_and_get_framework(
                params.framework_map, framework_name=params.framework_name
            )

        metadata = {}
        metadata_fields = []
        if params.framework_metadata:
            metadata_fields, metadata = get_metadata(params.framework_metadata)
        map_json = map(
            scf_data,
            data[0],
            params.framework_name,
            metadata_fields=metadata_fields,
            metadata=metadata,
        )
        if params.format == "json":
            output_result(params.output, map_json, "json")
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
                "Control - Very Low",
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
                csv_line = [framework_id, scf, co, c_vh, c_h, c_m, c_l, c_vl]

                # Append metadata values, using a safe default if a key is missing
                csv_line.extend(details.get(key, "") for key in metadata_fields)
                csv_lines.append(csv_line)

            output_result(params.output, csv_lines, "csv_list")

    elif params.operation == Operation.scan:
        output_result(params.output, scan_controls(params, data[0].get_json()), "json")

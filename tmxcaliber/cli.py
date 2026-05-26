import csv
import json
import os
import platform
import re
import sys
from argparse import ArgumentParser, ArgumentTypeError, Namespace, RawTextHelpFormatter
from base64 import b64decode
from collections.abc import Iterable
from importlib import metadata
from itertools import product
from shutil import rmtree
from typing import Any

from colorama import Fore

from . import parsers
from .lib.change_log import generate_change_log
from .lib.control_selector import resolve_control_ids
from .lib.errors import BinaryNotFound, FeatureClassCycleError
from .lib.filter import Filter
from .lib.filter_applier import FilterApplier
from .lib.scf import get_scf_data
from .lib.threatmodel_data import (
    ThreatModelData,
    get_classified_cvssed_control_ids_by_co,
)
from .lib.tools import sort_by_id
from .opacity import generate_pngs, generate_xml
from .params import (
    GUARDDUTY_FINDINGS,
    GUARDDUTY_PATTERN_NAME,
    IMG_DIR,
    METADATA_MISSING,
    MISSING_OUTPUT_ERROR,
    XML_DIR,
    ListOperation,
    Operation,
)

JsonDict = dict[str, Any]


def _get_version() -> str:
    module_name = vars(sys.modules[__name__])["__package__"]
    try:
        version = metadata.version(module_name)
        return f"{module_name} {version}"
    except metadata.PackageNotFoundError:
        return f"{module_name} version not found"


def get_params() -> Namespace:
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


def get_metadata(csv_path: str) -> tuple[list[str], dict[str, dict[str, str]]]:
    """
    Read a CSV file and return field names beyond the first column plus a
    dictionary keyed by the first column's values.

    Parameters:
        csv_path: The path to the CSV file.

    Returns:
        A tuple ``(fields_beyond_id, result)`` where ``fields_beyond_id`` is
        the list of fields after the first column and ``result`` is the parsed
        CSV data keyed by the first column.
    """
    result: dict[str, dict[str, str]] = {}
    fields_beyond_id: list[str] = []

    with open(csv_path, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        # Capture field names beyond the first one
        if reader.fieldnames is None:
            return [], {}
        fields_beyond_id = list(reader.fieldnames[1:])
        first_field = reader.fieldnames[0]

        # Process each row in the CSV
        for row in reader:
            # Remove and get the value of the first column for use as the main key
            main_key = row.pop(first_field)

            # Check if the main key already exists in the dictionary
            if main_key in result:
                # Update the existing dictionary with new values when missing
                for key, value in row.items():
                    if key not in result[main_key]:
                        result[main_key][key] = value
            else:
                # Add the new key and dictionary to the result
                result[main_key] = row

    return fields_beyond_id, result


def validate_and_get_framework(
    csv_path: str, framework_name: str
) -> list[tuple[str, str]]:
    del framework_name  # Kept for compatibility with existing call sites.

    def split_cell(value: str) -> list[str]:
        if not isinstance(value, str):
            return []

        normalized_value = value.strip()
        if normalized_value.lower() in {"", "none", "null", "nan", "n/a"}:
            return []

        return [
            part
            for part in (cell.strip() for cell in normalized_value.split(";"))
            if part and part.lower() not in {"none", "null", "nan", "n/a"}
        ]

    expanded_rows: list[tuple[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()

    with open(csv_path, newline="", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if not row or not any(str(value).strip() for value in row):
                continue

            if len(row) != 2:
                raise ValueError(
                    f"The CSV file at {csv_path} should have exactly 2 columns. "
                    "The SCF on the first, and your framework in the second."
                )

            scf_parts = split_cell(row[0])
            framework_parts = split_cell(row[1])

            if not scf_parts or not framework_parts:
                continue

            for pair in product(scf_parts, framework_parts):
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                expanded_rows.append(pair)

    return expanded_rows


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
                "Only the XML from the main ThreatModel can be used to "
                "generate DFD images."
            )
    elif args.operation == Operation.list:
        if args.list_type == ListOperation.threats:
            args.filter_obj = Filter(severity=args.severity, ids=args.ids)
        if args.list_type == ListOperation.controls:
            args.filter_obj = Filter(ids=args.ids)
    return args


def map(
    framework2co: Iterable[tuple[str, str]],
    threatmodel_data: ThreatModelData,
    framework_name: str,
    metadata_fields: list[str] | None = None,
    metadata: dict[str, dict[str, str]] | None = None,
) -> dict[str, dict[str, Any]]:
    controls, objectives = (
        threatmodel_data.controls,
        threatmodel_data.control_objectives,
    )
    scf_to_frameworks: dict[str, list[str]] = {}
    for scf_code, framework_id in framework2co:
        if not isinstance(scf_code, str) or not isinstance(framework_id, str):
            continue
        scf_to_frameworks.setdefault(scf_code, []).append(framework_id)

    grouped_frameworks: dict[str, dict[str, list[str]]] = {}
    for objective_id, values in objectives.items():
        scf_codes = values["scf"]
        if isinstance(scf_codes, str):
            scf_codes = [scf_codes]

        for scf_code in scf_codes:
            if not isinstance(scf_code, str):
                continue
            for framework_id in scf_to_frameworks.get(scf_code, []):
                if framework_id not in grouped_frameworks:
                    grouped_frameworks[framework_id] = {
                        "control_objectives": [],
                        "scf": [],
                    }
                grouped_frameworks[framework_id]["control_objectives"].append(
                    objective_id
                )
                grouped_frameworks[framework_id]["scf"].append(scf_code)

    # Prepare the new structure with SCFs included
    framework_map: dict[str, dict[str, Any]] = {}
    for framework in sorted(grouped_frameworks.keys()):
        data = grouped_frameworks[framework]
        framework_map[framework] = {
            "control_objectives": sort_by_id(list(set(data["control_objectives"]))),
            "scf": sorted(set(data["scf"])),
        }

        # Classify controls by severity
        control_id_by_cvss_severity: dict[str, list[str]] = {}
        for co_id in framework_map[framework]["control_objectives"]:
            control_id_by_cvss_severity = get_classified_cvssed_control_ids_by_co(
                control_id_by_cvss_severity, co_id, controls
            )
        framework_map[framework]["controls"] = control_id_by_cvss_severity

    if metadata:
        fields = metadata_fields or []
        for metadata_id, values in framework_map.items():
            if metadata_id in metadata:
                if isinstance(values, dict):
                    # Merge metadata into the existing dictionary
                    values.update(metadata[metadata_id])
                else:
                    print(
                        f"Error: Expected a dictionary at "
                        f"framework_map['{metadata_id}'], "
                        f"but found {type(values)}."
                    )
            else:
                for metadata_field in fields:
                    framework_map[metadata_id][metadata_field] = METADATA_MISSING

    return framework_map


def scan_controls(args: Namespace, data: JsonDict) -> JsonDict:
    if args.pattern == GUARDDUTY_PATTERN_NAME:
        pattern = re.compile(GUARDDUTY_FINDINGS)
    else:
        pattern = re.compile(args.pattern)
    controls: JsonDict = data["controls"]
    matched_controls: JsonDict = {}

    for control_id, control in controls.items():
        if pattern.search(control.get("description", "")):
            matched_controls[control_id] = control

    return {"controls": matched_controls}


def repair_json_strings(input_str: str) -> JsonDict:
    # In case the URL are replaced poorly by an email gateway.
    pattern = re.compile(r"(href=\\\"[^\"]*)")

    def replace_angle(match: re.Match[str]) -> str:
        return f"{match.group(1)}\\"

    repaired_str = pattern.sub(replace_angle, input_str)
    parsed_json: JsonDict = json.loads(repaired_str)
    return parsed_json


def load_json_data(json_file_path: str) -> JsonDict:
    try:
        with open(json_file_path) as f:
            file_content = f.read()
            try:
                data: JsonDict = json.loads(file_content)
                return data
            except json.JSONDecodeError:
                print(
                    f"Invalid JSON data in file: {json_file_path}. Trying to repair..."
                )
                try:
                    repaired_json = repair_json_strings(file_content)
                    print("Repair successful!")
                    return repaired_json
                except json.JSONDecodeError:
                    print("Repair failed. Exiting.")
                    sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {json_file_path}")
        sys.exit(1)


def get_file_paths(source: str) -> list[str]:
    if os.path.isdir(source):
        return sorted(
            os.path.join(source, f) for f in os.listdir(source) if f.endswith(".json")
        )
    if os.path.isfile(source) and source.endswith(".json"):
        return [source]
    return []


def load_json_files(json_file_paths: list[str]) -> list[ThreatModelData]:
    threatmodel_data_list: list[ThreatModelData] = []
    for json_file_path in json_file_paths:
        data = load_json_data(json_file_path)
        threatmodel_data_list.append(ThreatModelData(data))
    return threatmodel_data_list


def get_recursive_json_file_paths(source: str) -> list[str]:
    if os.path.isfile(source):
        if source.lower().endswith(".json"):
            return [os.path.abspath(source)]
        print(f"Invalid file type for {source}")
        sys.exit(1)

    json_file_paths: list[str] = []
    for root, _, files in os.walk(source):
        for filename in files:
            if filename.lower().endswith(".json"):
                json_file_paths.append(os.path.abspath(os.path.join(root, filename)))
    return sorted(json_file_paths)


def get_service_rows(source: str) -> list[dict[str, str]]:
    service_rows: list[dict[str, str]] = []

    for json_file_path in get_recursive_json_file_paths(source):
        data = load_json_data(json_file_path)
        metadata_block = data.get("metadata", {})
        if not isinstance(metadata_block, dict):
            continue

        names: list[str] = []
        primary_name = metadata_block.get("service_name")
        if isinstance(primary_name, str):
            primary_name = primary_name.strip()
            if primary_name:
                names.append(primary_name)

        other_services = metadata_block.get("other_covered_services", [])
        if isinstance(other_services, list):
            for service_name in other_services:
                if not isinstance(service_name, str):
                    continue
                service_name = service_name.strip()
                if service_name and service_name not in names:
                    names.append(service_name)

        for service_name in names:
            service_rows.append({"name": service_name, "file": json_file_path})

    return service_rows


def get_feature_class_rows(source: str) -> list[dict[str, str]]:
    data = load_json_data(source)
    feature_classes = data.get("feature_classes", {})
    if not isinstance(feature_classes, dict):
        return []

    feature_class_rows: list[dict[str, str]] = []
    for feature_class_id, feature_class in feature_classes.items():
        name = ""
        description = ""
        if isinstance(feature_class, dict):
            if isinstance(feature_class.get("name"), str):
                name = feature_class["name"]
            if isinstance(feature_class.get("description"), str):
                description = feature_class["description"]

        feature_class_rows.append(
            {
                "id": feature_class_id,
                "name": name,
                "description": description,
            }
        )

    return feature_class_rows


def get_input_data(
    params: Namespace,
) -> list[ThreatModelData] | str | dict[str, list[ThreatModelData] | str]:
    all_sources: dict[str, str] = {}
    if hasattr(params, "source") and params.source:
        all_sources["source"] = params.source

    if hasattr(params, "new_source") and params.new_source:
        all_sources["new_source"] = params.new_source

    if hasattr(params, "old_source") and params.old_source:
        all_sources["old_source"] = params.old_source

    all_data: dict[str, list[ThreatModelData] | str] = {}
    for key, source in all_sources.items():
        if not os.path.exists(source):
            print(f"File or directory not found: {source}")
            sys.exit(1)

        json_file_paths = get_file_paths(source)

        if params.operation != "list" and len(json_file_paths) > 1:
            raise ArgumentTypeError(f"Only 1 file can be given for {params.operation}")

        if json_file_paths:
            all_data[key] = load_json_files(json_file_paths)
        elif source.endswith(".xml"):
            with open(source) as file:
                all_data[key] = file.read()
        else:
            print(f"Invalid file type for {source}")
            sys.exit(1)

    if "source" in all_data:
        return all_data["source"]
    return all_data


def get_drawio_binary_path() -> str:
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
        "drawio binary not found automatically. Use --bin flag to specify "
        "path to drawio binary."
    )


def output_result(
    output_param: str | None,
    result: Any,
    result_type: str,
    output_removed_json: JsonDict | None = None,
) -> None:
    removed_json = output_removed_json or {}
    json_result = ""
    output_removed_result = ""
    csv_result: list[list[Any]] = []
    markdown = ""
    is_json = False
    is_csv = False
    is_md = False
    if result_type == "json":
        json_result = json.dumps(result, indent=2)
        if removed_json:
            output_removed_result = json.dumps(removed_json, indent=2)
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
            if removed_json:
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


def main() -> None:
    params = get_params()
    if (
        params.operation == Operation.list
        and params.list_type == ListOperation.services
    ):
        service_rows = get_service_rows(params.source)
        if params.format == "json":
            output_result(params.output, service_rows, "json")
        else:
            csv_output: list[list[Any]] = [["name", "file"]]
            csv_output.extend([[row["name"], row["file"]] for row in service_rows])
            output_result(params.output, csv_output, "csv_list")
        return
    if (
        params.operation == Operation.list
        and params.list_type == ListOperation.feature_classes
    ):
        feature_class_rows = get_feature_class_rows(params.source)
        if params.format == "json":
            output_result(params.output, feature_class_rows, "json")
        else:
            csv_output = [["id", "name", "description"]]
            csv_output.extend(
                [
                    [row["id"], row["name"], row["description"]]
                    for row in feature_class_rows
                ]
            )
            output_result(params.output, csv_output, "csv_list")
        return

    try:
        data = get_input_data(params)
    except FeatureClassCycleError as exc:
        raise SystemExit(exc) from exc

    if params.operation == Operation.add_mapping:
        # If SCF-supported framework, fetch the data; otherwise map directly.
        scf_data: Iterable[tuple[str, str]]
        if not params.framework_map:
            scf_data = get_scf_data(params.scf, framework_name=params.framework_name)
        else:
            scf_data = validate_and_get_framework(
                params.framework_map, framework_name=params.framework_name
            )

        metadata_dict: dict[str, dict[str, str]] = {}
        metadata_fields: list[str] = []
        if params.framework_metadata:
            metadata_fields, metadata_dict = get_metadata(params.framework_metadata)

        assert isinstance(data, list)
        threatmodel_data = data[0]
        map_json = map(
            scf_data,
            threatmodel_data,
            params.framework_name,
            metadata_fields=metadata_fields,
            metadata=metadata_dict,
        )

        threatmodel_data.threatmodel_json["mapping"] = {}
        for key in sorted(map_json.keys()):
            # Extract everything except the 'controls' subkey
            new_entry = {k: v for k, v in map_json[key].items() if k != "controls"}
            threatmodel_data.threatmodel_json["mapping"][key] = new_entry

        for co in threatmodel_data.control_objectives:
            framework_controls: list[str] = []
            for fw_control in map_json:
                if co in (map_json[fw_control].get("control_objectives") or []):
                    framework_controls.append(fw_control)
            threatmodel_data.threatmodel_json["control_objectives"][co][
                params.framework_name
            ] = sorted(set(framework_controls))

        output_result(params.output, threatmodel_data.threatmodel_json, "json")

    elif params.operation == Operation.create_change_log:
        assert isinstance(data, dict)
        old_tm_data = data["old_source"]
        new_tm_data = data["new_source"]
        assert isinstance(old_tm_data, list)
        assert isinstance(new_tm_data, list)
        old_model = old_tm_data[0]
        new_model = new_tm_data[0]
        FilterApplier(params.filter_obj, params.exclude).apply_filter(old_model)
        FilterApplier(params.filter_obj, params.exclude).apply_filter(new_model)
        change_log = generate_change_log(old_model.get_json(), new_model.get_json())
        if params.format == "json":
            output_result(params.output, change_log.get_json(), "json")
        elif params.format == "md":
            output_result(params.output, change_log.get_md(), "md")

    elif params.operation == Operation.filter:
        assert isinstance(data, list)
        threatmodel_data = data[0]
        FilterApplier(params.filter_obj, params.exclude).apply_filter(threatmodel_data)
        removed_json: JsonDict = {}
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
                sys.exit(1)
        else:
            binary = params.bin

        provider = ""
        service = ""
        main_xml = ""
        if isinstance(data, str):
            main_xml = data
            filename = os.path.basename(params.source)
            parts = filename.split("_DFD.xml")
            if len(parts) != 2:
                print(
                    "Invalid XML filename format. "
                    "Expected format: {provider}_{service}_DFD.xml"
                )
                sys.exit(1)
            provider, service = parts[0].split("_", 1)

        elif isinstance(data, list):
            provider = data[0].threatmodel_json.get("metadata", {}).get("provider")
            service = data[0].threatmodel_json.get("metadata", {}).get("service")
            if not (provider and service):
                print("No `provider` or `service` in the JSON data.")
                sys.exit(1)

            body = data[0].threatmodel_json.get("dfd", {}).get("body")
            if not body:
                print("Could not get `dfd.body` from the JSON data.")
                sys.exit(1)

            try:
                main_xml = b64decode(body).decode("utf8")
            except ValueError:
                print("Invalid XML data provided in the JSON.")
                sys.exit(1)

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
        models: list[ThreatModelData] = data if isinstance(data, list) else []
        ThreatModelData.threatmodel_data_list = models

        csv_output = []
        if params.list_type == ListOperation.threats:
            for threatmodel_data in models:
                FilterApplier(params.filter_obj, params.exclude).apply_filter(
                    threatmodel_data
                )
            csv_output = ThreatModelData.get_csv_of_threats()

        if params.list_type == ListOperation.controls:
            ids_were_provided = bool(getattr(params, "ids", None))
            control_ids = resolve_control_ids(
                models,
                list_type=params.type,
                filter_obj=params.filter_obj,
                exclude=params.exclude,
                ids_were_provided=ids_were_provided,
            )
            csv_output = ThreatModelData.get_csv_of_controls(control_ids, exclude=False)

        output_result(params.output, csv_output, "csv_list")

    elif params.operation == Operation.map:
        # If SCF-supported framework, fetch the data; otherwise map directly.
        if not params.framework_map:
            scf_data = get_scf_data(params.scf, framework_name=params.framework_name)
        else:
            scf_data = validate_and_get_framework(
                params.framework_map, framework_name=params.framework_name
            )

        metadata_dict = {}
        metadata_fields = []
        if params.framework_metadata:
            metadata_fields, metadata_dict = get_metadata(params.framework_metadata)

        assert isinstance(data, list)
        map_json = map(
            scf_data,
            data[0],
            params.framework_name,
            metadata_fields=metadata_fields,
            metadata=metadata_dict,
        )
        if params.format == "json":
            output_result(params.output, map_json, "json")
        if params.format == "csv":
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

            csv_lines: list[list[Any]] = []
            csv_lines.append(titles + list(metadata_fields))

            for framework_id, details in map_json.items():
                scf = ";".join(details.get("scf", []))
                co = ";".join(details.get("control_objectives", []))
                controls = details.get("controls", {})
                c_vh = ";".join(controls.get("Very High", []))
                c_h = ";".join(controls.get("High", []))
                c_m = ";".join(controls.get("Medium", []))
                c_l = ";".join(controls.get("Low", []))
                c_vl = ";".join(controls.get("Very Low", []))

                csv_line: list[Any] = [
                    framework_id,
                    scf,
                    co,
                    c_vh,
                    c_h,
                    c_m,
                    c_l,
                    c_vl,
                ]

                csv_line.extend(details.get(key, "") for key in metadata_fields)
                csv_lines.append(csv_line)

            output_result(params.output, csv_lines, "csv_list")

    elif params.operation == Operation.scan:
        assert isinstance(data, list)
        output_result(params.output, scan_controls(params, data[0].get_json()), "json")

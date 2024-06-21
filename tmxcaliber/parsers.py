from argparse import ArgumentParser, ArgumentTypeError, RawTextHelpFormatter
import csv
import os
from .params import Operation, ListOperation, GUARDDUTY_PATTERN_NAME, XML_DIR, IMG_DIR
from .lib.scf import get_supported_scf
from .lib.filter import (
    IDS_INPUT_SEPARATOR,
    EVENTS_INPUT_SEPARATOR,
    PERMISSIONS_INPUT_SEPARATOR,
)


def add_add_mapping_parser(subparsers):
    add_mapping_parser = subparsers.add_parser(
        Operation.add_mapping,
        help="add a supported framework in the Secure Control Framework (https://securecontrolsframework.com) into the ThreatModel JSON data.",
        formatter_class=RawTextHelpFormatter,
    )
    add_scf_argument(add_mapping_parser)
    add_framework_argument(add_mapping_parser)
    add_metadata_argument(add_mapping_parser)
    add_source_argument(add_mapping_parser)
    add_output_argument(add_mapping_parser)


def add_changelog_parser(subparsers):
    changelog_parser = subparsers.add_parser(
        Operation.create_change_log,
        help="create the change log between 2 ThreatModel data.",
        formatter_class=RawTextHelpFormatter,
    )
    add_source_new_argument(changelog_parser)
    add_source_old_argument(changelog_parser)
    add_format_argument(
        changelog_parser,
        choices=["json", "md"],
        default="json",
        help="format to output (default to JSON)",
    )
    add_output_argument(changelog_parser)
    add_ids_filter_argument(changelog_parser)
    add_exclude_flag(changelog_parser)


def add_filter_parser(subparsers):
    filter_parser = subparsers.add_parser(
        Operation.filter,
        help="filter down the ThreatModel data.",
        formatter_class=RawTextHelpFormatter,
    )

    filter_parser.add_argument(
        "--output-removed",
        action="store_true",
        help="flag to output all the removed information into another file. Require --output.",
    )
    filter_parser.add_argument(
        "--permissions",
        type=str,
        help=(
            "filter data by IAM permission(s). "
            f"Separate by `{PERMISSIONS_INPUT_SEPARATOR}`, if several.\n\n"
        ),
    )
    filter_parser.add_argument(
        "--events",
        type=str,
        help=(
            "filter data by actions log events. "
            f"Separate by `{EVENTS_INPUT_SEPARATOR}`, if several.\n\n"
        ),
    )
    add_output_argument(filter_parser)
    add_source_argument(filter_parser)
    add_severity_filter_argument(filter_parser)
    add_ids_filter_argument(filter_parser)
    add_exclude_flag(filter_parser)


def add_gen_parser(subparsers):
    gen_parser = subparsers.add_parser(
        Operation.generate,
        help="generate threat specific PNGs from XML data.",
        formatter_class=RawTextHelpFormatter,
    )
    gen_parser.add_argument(
        "--bin", help="path to `drawio` binary (if not detected automatically)"
    )
    gen_parser.add_argument(
        "--threat-dir",
        default=XML_DIR,
        help="output dir for threat files "
        f"(.{os.path.join(os.path.sep, os.path.basename(XML_DIR))})",
    )
    gen_parser.add_argument(
        "--fc-dir",
        default=XML_DIR,
        help="output dir for feature class files "
        f"(.{os.path.join(os.path.sep, os.path.basename(XML_DIR))})",
    )
    gen_parser.add_argument(
        "--validate",
        default=False,
        action="store_true",
        help="flag indicating whether to do validation or not.",
    )
    gen_parser.add_argument(
        "--out-dir",
        default=IMG_DIR,
        help="output dir for PNG files "
        f"(.{os.path.join(os.path.sep, os.path.basename(IMG_DIR))})",
    )
    add_source_argument(gen_parser)


def add_list_parser(subparsers):
    list_parser = subparsers.add_parser(
        Operation.list,
        help="List data of one or more ThreatModels.",
        formatter_class=RawTextHelpFormatter,
    )
    list_subparsers = list_parser.add_subparsers(
        title="list_type", dest="list_type", required=True
    )

    def add_list_threats_parser(list_subparsers):
        threat_list_parser = list_subparsers.add_parser(
            ListOperation.threats,
            help="List threat data of one or more ThreatModels.",
            formatter_class=RawTextHelpFormatter,
        )
        add_source_json_or_dir_argument(threat_list_parser)
        add_output_argument(threat_list_parser)
        add_exclude_flag(threat_list_parser)
        add_severity_filter_argument(threat_list_parser)
        add_ids_filter_argument(threat_list_parser)

    def add_list_controls_parser(list_subparsers):
        control_list_parser = list_subparsers.add_parser(
            ListOperation.controls,
            help="List control data of one or more ThreatModels.",
            formatter_class=RawTextHelpFormatter,
        )
        add_source_json_or_dir_argument(control_list_parser)
        add_output_argument(control_list_parser)
        add_exclude_flag(control_list_parser)
        add_ids_filter_argument(control_list_parser)

    add_list_threats_parser(list_subparsers)
    add_list_controls_parser(list_subparsers)


def add_map_parser(subparsers):
    map_parser = subparsers.add_parser(
        Operation.map,
        help="map ThreatModel data to a supported framework in the Secure Control Framework (https://securecontrolsframework.com).",
        formatter_class=RawTextHelpFormatter,
    )
    add_scf_argument(map_parser)
    add_framework_argument(map_parser)
    add_metadata_argument(map_parser)
    map_parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv"],
        default="csv",
        help="format to output (default to CSV).",
    )
    add_output_argument(map_parser)
    add_source_argument(map_parser)


def add_scan_parser(subparsers):
    scan_parser = subparsers.add_parser(
        Operation.scan,
        help="scan the ThreatModel data for a given pattern.",
        formatter_class=RawTextHelpFormatter,
    )
    scan_parser.add_argument(
        "--pattern",
        type=str,
        required=True,
        help=(
            "regex pattern to find in control descriptions.\n"
            f"For GuardDuty findings, use the pattern: {GUARDDUTY_PATTERN_NAME}\n\n"
        ),
    )
    add_source_argument(scan_parser)
    add_output_argument(scan_parser)


def valid_csv_path(file_path):
    try:
        with open(file_path, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            first_row = next(reader, None)  # Read the first row
            if first_row is None:
                raise ValueError("CSV file is empty and missing a first row.")

            first_row_count = len(first_row)
            if first_row_count == 0:
                raise ValueError("First row is present but contains no columns.")

            # Track row lengths to check for consistency throughout
            row_lengths = set()

            for i, row in enumerate(reader, start=1):
                row_length = len(row)
                if row_length != first_row_count:
                    raise ValueError(
                        f"Row {i} does not match first row column count. Found {row_length} columns, expected {first_row_count}."
                    )

                # Optionally add to a set to check for varied lengths
                row_lengths.add(row_length)

            # Additional check to see if any discrepancies in row lengths
            if len(row_lengths) > 1:
                raise ValueError("Inconsistent number of columns across rows.")

    except FileNotFoundError:
        raise ArgumentTypeError("The specified file does not exist.")
    except csv.Error as e:
        raise ArgumentTypeError(f"CSV parsing error: {e}")
    except Exception as e:
        raise ArgumentTypeError(f"An error occurred while validating the CSV file: {e}")

    return file_path


def is_file(path: str) -> str:
    if not os.path.exists(path):
        raise ArgumentTypeError(f"The path {path} does not exist.")
    if not os.path.isfile(path):
        raise ArgumentTypeError(f"The path {path} is not a file.")
    if os.path.isfile(path) and not (
        path.lower().endswith(".json") or path.lower().endswith(".xml")
    ):
        raise ArgumentTypeError(
            f"The file {path} is not valid, only json or XML can be given."
        )
    return path


def is_file_or_dir(path: str) -> str:
    if not os.path.exists(path):
        raise ArgumentTypeError(f"The path {path} does not exist.")
    if not (os.path.isfile(path) or os.path.isdir(path)):
        raise ArgumentTypeError(f"The path {path} is neither a file nor a directory.")
    if os.path.isfile(path) and not (
        path.lower().endswith(".json") or path.lower().endswith(".xml")
    ):
        raise ArgumentTypeError(
            f"The file {path} is not valid, only json or xml can be given."
        )
    return path


def add_exclude_flag(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--exclude",
            action="store_true",
            help="Enable exclusion mode. Items specified will be excluded from the output.",
        )


def add_format_argument(*parsers: ArgumentParser, choices, default, help):
    for parser in parsers:
        parser.add_argument(
            "--format",
            type=str,
            choices=choices,
            default=default,
            help=help,
        )


def add_framework_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--framework-name",
            type=str,
            required=True,
            help=(
                "framework name to map to. Options are:\n"
                "1) the exact name present in the Secure Control Framework header (replace carriage returns by spaces), or\n"
                "2) your own framework name\n\n"
            ),
        )

        parser.add_argument(
            "--framework-map",
            type=valid_csv_path,
            help=(
                "path to a CSV file to your own framework map to SCF. No header row.\n"
                "only if you use your own framework.\n\n"
            ),
        )

        parser.add_argument(
            "--framework-metadata",
            type=valid_csv_path,
            help=(
                "path to a CSV file to add metadata into your mapping. Header row is used for titles.\n"
                "only if you use your own framework.\n\n"
            ),
        )


def add_ids_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--ids",
            type=str,
            help=(
                "filter data by IDs (can be feature classes, threats, controls, or control objectives). "
                f"Separate by `{IDS_INPUT_SEPARATOR}`, if several.\n\n"
            ),
        )


def add_metadata_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--metadata",
            type=valid_csv_path,
            help=(
                "path to a CSV file to add metadata into your mapping. Header row is used for titles.\n\n"
            ),
        )


def add_output_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--output",
            type=str,
            help="output file to write the results. If not provided, prints to stdout.",
        )


def add_scf_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--scf",
            type=str,
            required=True,
            choices=get_supported_scf(),
            help=("version of the Secure Control Framework\n\n"),
        )


def add_severity_filter_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--severity",
            type=str,
            choices=["very high", "high", "medium", "low", "very low"],
            help="filter data by threat for severity equal or above the selected value.\n\n",
        )


def add_source_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "source",
            type=is_file,
            help="path to the ThreatModel JSON file. We support XML file for internal purposes on some operations.",
        )


def add_source_new_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "new_source",
            type=is_file,
            help="path to the newer ThreatModel JSON file.",
        )


def add_source_old_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "old_source",
            type=is_file,
            help="path to the older ThreatModel JSON file.",
        )


def add_source_json_or_dir_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "source",
            type=is_file_or_dir,
            help="Path to the ThreatModel JSON file or directory containing ThreatModel JSON files.",
        )

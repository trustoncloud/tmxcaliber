from argparse import ArgumentParser, ArgumentTypeError
import csv
import os
from .lib.scf import get_supported_scf

def valid_csv_path(file_path):
    try:
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
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
                    raise ValueError(f"Row {i} does not match first row column count. Found {row_length} columns, expected {first_row_count}.")

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
    if os.path.isfile(path) and not (path.lower().endswith('.json') or path.lower().endswith('.xml')):
        raise ArgumentTypeError(f"The file {path} is not valid, only json or XML can be given.")
    return path

def add_source_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "source", type=is_file, 
            help="path to the ThreatModel JSON file. We support XML file for internal purposes on some operations."
        )

def add_output_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--output", type=str, help="output file to write the results. If not provided, prints to stdout."
        )

def add_scf_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--scf", type=str, required=True, choices=get_supported_scf(), help=(
                "version of the Secure Control Framework\n\n"
        ))

def add_framework_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--framework-name", type=str, required=True, help=(
                "framework name to map to. Options are:\n"
                "1) the exact name present in the Secure Control Framework header (replace carriage returns by spaces), or\n"
                "2) your own framework name\n\n"
            )
        )

        parser.add_argument(
            "--framework-map", type=valid_csv_path, help=(
                "path to a CSV file to your own framework map to SCF. No header row.\n"
                "only if you use your own framework.\n\n"
            )
        )

        parser.add_argument(
            "--framework-metadata", type=valid_csv_path, help=(
                "path to a CSV file to add metadata into your mapping. Header row is used for titles.\n"
                 "only if you use your own framework.\n\n"
            )
        )

def add_metadata_argument(*parsers: ArgumentParser):
    for parser in parsers:
        parser.add_argument(
            "--metadata", type=valid_csv_path, help=(
                "path to a CSV file to add metadata into your mapping. Header row is used for titles.\n\n"
            )
        )
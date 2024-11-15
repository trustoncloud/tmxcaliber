import re
import json
from datetime import datetime, timezone


def extract_number_from_tm_ids(s: str) -> int:
    # Use a regular expression to find all digits at the end of the string
    match = re.search(r"\d+$", s)
    # Return the number as an integer if found, otherwise return 0
    return int(match.group()) if match else 0


# Priority mapping for the letter segments
priority_map = {"FC": 1, "T": 2, "CO": 3, "C": 4, "A": 5}


def extract_letters_and_number(s: str) -> tuple:
    # Extract the part between the dot and the digits
    match = re.search(r"\.(\D+)(\d+)$", s)
    if match:
        letters, number = match.groups()
        return (1, priority_map.get(letters, float("inf")), int(number))
    # If the format is not matched, return 0 to sort them first by alphabetical order
    return (0, s, 0)


def sort_by_id(strings: list) -> list:
    # Sort the list of strings using the extracted number as the key
    return sorted(strings, key=extract_number_from_tm_ids)


def sort_dict_by_id(data_dict: dict) -> dict:
    # Sort the dictionary by extracting numbers from the keys using the provided extract_number function
    sorted_items = sorted(
        data_dict.items(), key=lambda item: extract_number_from_tm_ids(item[0])
    )
    # Rebuild the dictionary with sorted items
    return dict(sorted_items)


def sort_dict_list_by_id(
    data_dict_list: list, key: str, function=extract_letters_and_number
) -> list:
    # Sort the list of dictionaries based on the numerical value extracted from the specified key
    return sorted(
        data_dict_list, key=lambda d: function(d[key]) if key in d else (0, "", 0)
    )


def sort_list_by_id(list_of_lists: list, index: int) -> list:
    """
    Sorts a list of lists by the extracted letters and numbers at the specified index in each inner list.

    Parameters:
    - list_of_lists (list): The list of lists to sort.
    - index (int): The index in the inner lists to sort by, where each item is expected to be a string.

    Returns:
    - list: A sorted list of lists.
    """
    return sorted(
        list_of_lists,
        key=lambda x: (
            extract_letters_and_number(x[index])
            if index < len(x) and isinstance(x[index], str)
            else (0, "", 0)
        ),
    )


def convert_epoch_to_utc(seconds_epoch: int) -> str:
    utc_datetime = datetime.fromtimestamp(seconds_epoch, tz=timezone.utc)
    return utc_datetime.strftime("%Y-%m-%d-%H-%M-%S")


def apply_json_filter(original_json: dict, filter_json: dict) -> dict:
    """
    Recursively find differences in two JSON-like dictionaries, returning the
    parts of the original_json that are missing from the filter_json.

    Args:
    original_json (dict): The original_json JSON-like dictionary.
    filter_json (dict): The filter_json JSON-like dictionary.

    Returns:
    dict: A dictionary containing the differences.
    """
    if not isinstance(original_json, dict) or not isinstance(filter_json, dict):
        return original_json if original_json != filter_json else None

    diff = {}
    for key in original_json:
        if key not in filter_json:
            diff[key] = original_json[key]
        else:
            if isinstance(original_json[key], dict) and isinstance(
                filter_json[key], dict
            ):
                result = apply_json_filter(original_json[key], filter_json[key])
                if result:
                    diff[key] = result
            elif isinstance(original_json[key], list) and isinstance(
                filter_json[key], list
            ):
                # Handle lists possibly containing dictionaries
                # Convert list elements to set of strings (JSON) to allow comparison of dictionaries
                original_set = set(
                    json.dumps(elem, sort_keys=True) for elem in original_json[key]
                )
                filter_set = set(
                    json.dumps(elem, sort_keys=True) for elem in filter_json[key]
                )
                if original_set != filter_set:
                    # Convert JSON strings back to dictionaries for the result
                    diff[key] = [json.loads(elem) for elem in original_set - filter_set]
            elif original_json[key] != filter_json[key]:
                diff[key] = original_json[key]

    return diff

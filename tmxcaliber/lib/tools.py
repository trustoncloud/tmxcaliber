import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

T = TypeVar("T")

# Priority mapping for the letter segments
priority_map: dict[str, int] = {"FC": 1, "T": 2, "CO": 3, "C": 4, "A": 5}

SortKey = tuple[int, int | float | str, int]


def extract_number_from_tm_ids(s: str) -> int:
    # Use a regular expression to find all digits at the end of the string
    match = re.search(r"\d+$", s)
    # Return the number as an integer if found, otherwise return 0
    return int(match.group()) if match else 0


def extract_letters_and_number(s: str) -> SortKey:
    # Extract the part between the dot and the digits
    match = re.search(r"\.(\D+)(\d+)$", s)
    if match:
        letters, number = match.groups()
        return (1, priority_map.get(letters, float("inf")), int(number))
    # If the format is not matched, sort them first by alphabetical order
    return (0, s, 0)


def sort_by_id(strings: list[str]) -> list[str]:
    # Sort the list of strings using the extracted number as the key
    return sorted(strings, key=extract_number_from_tm_ids)


def sort_dict_by_id(data_dict: dict[str, T]) -> dict[str, T]:
    # Sort the dictionary by extracting numbers from the keys
    sorted_items = sorted(
        data_dict.items(), key=lambda item: extract_number_from_tm_ids(item[0])
    )
    # Rebuild the dictionary with sorted items
    return dict(sorted_items)


def sort_dict_list_by_id(
    data_dict_list: list[dict[str, Any]],
    key: str,
    function: Callable[[str], SortKey] = extract_letters_and_number,
) -> list[dict[str, Any]]:
    # Sort the list of dictionaries by the numerical value extracted from the
    # specified key
    return sorted(
        data_dict_list, key=lambda d: function(d[key]) if key in d else (0, "", 0)
    )


def sort_list_by_id(list_of_lists: list[list[Any]], index: int) -> list[list[Any]]:
    """
    Sorts a list of lists by the letters and numbers extracted at the given index
    of each inner list.

    Parameters:
    - list_of_lists (list): The list of lists to sort.
    - index (int): The position in each inner list whose string value is the
      sort key.

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


def apply_json_filter(
    original_json: dict[str, Any], filter_json: dict[str, Any]
) -> dict[str, Any]:
    """
    Recursively find differences in two JSON-like dictionaries, returning the
    parts of the original_json that are missing from the filter_json.

    Args:
        original_json: The original JSON-like dictionary.
        filter_json: The filter JSON-like dictionary.

    Returns:
        A dictionary containing the differences.
    """
    diff: dict[str, Any] = {}
    for key in original_json:
        if key not in filter_json:
            diff[key] = original_json[key]
            continue

        orig_value = original_json[key]
        filt_value = filter_json[key]

        if isinstance(orig_value, dict) and isinstance(filt_value, dict):
            result = apply_json_filter(orig_value, filt_value)
            if result:
                diff[key] = result
        elif isinstance(orig_value, list) and isinstance(filt_value, list):
            # Handle lists possibly containing dictionaries. Convert list
            # elements to a set of JSON strings to allow comparison.
            original_set = {json.dumps(elem, sort_keys=True) for elem in orig_value}
            filter_set = {json.dumps(elem, sort_keys=True) for elem in filt_value}
            if original_set != filter_set:
                diff[key] = [json.loads(elem) for elem in original_set - filter_set]
        elif orig_value != filt_value:
            diff[key] = orig_value

    return diff

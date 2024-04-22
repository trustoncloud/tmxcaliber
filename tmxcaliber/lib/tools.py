import re

def extract_number(s: str) -> int:
    # Use a regular expression to find all digits at the end of the string
    match = re.search(r'\d+$', s)
    # Return the number as an integer if found, otherwise return 0
    return int(match.group()) if match else 0

def sort_by_id(strings: list) -> list:
    # Sort the list of strings using the extracted number as the key
    return sorted(strings, key=extract_number)

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
            if isinstance(original_json[key], dict) and isinstance(filter_json[key], dict):
                result = apply_json_filter(original_json[key], filter_json[key])
                if result:
                    diff[key] = result
            elif original_json[key] != filter_json[key]:
                if isinstance(original_json[key], list) and isinstance(filter_json[key], list):
                    # Handle lists by comparing element-wise
                    if set(original_json[key]) != set(filter_json[key]):
                        diff[key] = list(set(original_json[key]) - set(filter_json[key]))
                else:
                    diff[key] = original_json[key]

    return diff
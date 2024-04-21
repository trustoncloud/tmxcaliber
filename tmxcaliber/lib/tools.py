import re

def extract_number(s):
    # Use a regular expression to find all digits at the end of the string
    match = re.search(r'\d+$', s)
    # Return the number as an integer if found, otherwise return 0
    return int(match.group()) if match else 0

def sort_by_id(strings):
    # Sort the list of strings using the extracted number as the key
    return sorted(strings, key=extract_number)
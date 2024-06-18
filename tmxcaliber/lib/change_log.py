
from deepdiff import DeepDiff

def safe_get(d, keys):
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key, {})
        else:
            return {}
    return d

# Function to generate a structured change log
def generate_change_log(json1, json2):
    diff = DeepDiff(json1, json2, ignore_order=True, report_repetition=True)
    change_log = []

    # Mapping for change types
    change_type_map = {
        "dictionary_item_added": "Added",
        "dictionary_item_removed": "Removed",
        "values_changed": "Modified",
        "type_changes": "Type Changed",
        "iterable_item_added": "Added",
        "iterable_item_removed": "Removed",
    }

    # Process differences
    for change_type, changes in diff.items():
        if isinstance(changes, dict):
            for key, value in changes.items():
                key_parts = key.split("['")
                category = key_parts[1].replace("']", "") if len(key_parts) > 1 else "root"
                identifier = key_parts[2].replace("']", "") if len(key_parts) > 2 else ""
                field_path = "['".join(key_parts[3:]).replace("']", "").replace("['", "/")

                if "mitigate" in field_path:
                    print(field_path)
                    exit(0)
                    # Extract the specific threat value instead of list position
                    threat_value = ""
                    mitigate_items = safe_get(json1, [category, identifier, "mitigate"])
                    if isinstance(mitigate_items, list):
                        for item in mitigate_items:
                            if "mitigate" in key:
                                threat_value = item.get("threat", "")
                                break
                    field_path = field_path.replace("mitigate/", f"mitigate[{threat_value}]/")

                change_entry = {
                    "action_summary": change_type_map.get(change_type, "Unknown"),
                    "category": category,
                    "identifier": identifier,
                    "field_changes": {}
                }

                if change_type in ["dictionary_item_added", "dictionary_item_removed"]:
                    change_entry["field_changes"][field_path] = value
                elif change_type in ["values_changed", "type_changes"]:
                    change_entry["field_changes"][field_path] = {
                        "old_value": value.get("old_value"),
                        "new_value": value.get("new_value")
                    }
                change_log.append(change_entry)
        elif isinstance(changes, list):
            for item in changes:
                key_parts = item.split("['")
                category = key_parts[1].replace("']", "") if len(key_parts) > 1 else "root"
                identifier = key_parts[2].replace("']", "") if len(key_parts) > 2 else ""
                field_path = "['".join(key_parts[3:]).replace("']", "").replace("['", "/")

                if "mitigate" in field_path:
                    # Extract the specific threat value instead of list position
                    threat_value = ""
                    mitigate_items = safe_get(json1, [category, identifier, "mitigate"])
                    if isinstance(mitigate_items, list):
                        for item in mitigate_items:
                            if "mitigate" in key:
                                threat_value = item.get("threat", "")
                                break
                    field_path = field_path.replace("mitigate/", f"mitigate[{threat_value}]/")

                change_entry = {
                    "action_summary": change_type_map.get(change_type, "Unknown"),
                    "category": category,
                    "identifier": identifier,
                    "field_changes": {}
                }

                if change_type in ["dictionary_item_added", "dictionary_item_removed"]:
                    change_entry["field_changes"][field_path] = item
                elif change_type in ["values_changed", "type_changes"]:
                    change_entry["field_changes"][field_path] = {
                        "old_value": item.get("old_value"),
                        "new_value": item.get("new_value")
                    }
                change_log.append(change_entry)

    return {'change_log': change_log}

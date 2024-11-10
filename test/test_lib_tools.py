from tmxcaliber.lib.tools import (
    apply_json_filter,
    extract_letters_and_number,
    sort_by_id,
    sort_dict_by_id,
    sort_dict_list_by_id,
    sort_list_by_id,
    convert_epoch_to_utc,
)


def test_json_modification():
    original_json = {
        "controls": {
            "someservice.C1": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            },
            "someservice.C2": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            },
            "someservice.C3": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            },
        },
        "control_objectives": {"someservice.CO1": {"scf": ["SCF1"]}},
    }

    assert apply_json_filter(original_json, {}) == original_json

    filter_json = {
        "controls": {
            "someservice.C1": {
                "feature_class": [
                    "someservice.FC1",
                    "someservice.FC2",
                ],  # added new feature class
                "objective": "someservice.CO1",
                "weighted_priority": "Medium",  # changed priority
            },
            "someservice.C2": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            },
        },
        "control_objectives": {
            "someservice.CO1": {"scf": ["SCF2"]}
        },  # changed scf value
    }

    expected_diff = {
        "controls": {
            "someservice.C1": {"feature_class": [], "weighted_priority": "High"},
            "someservice.C3": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            },
        },
        "control_objectives": {"someservice.CO1": {"scf": ["SCF1"]}},
    }

    assert apply_json_filter(original_json, filter_json) == expected_diff


def test_json_addition():
    original_json = {
        "controls": {
            "someservice.C1": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            }
        },
        "control_objectives": {"someservice.CO1": {"scf": ["SCF1"]}},
    }

    # Adding a new control
    filter_json = {
        "controls": {
            "someservice.C1": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            },
            "someservice.C2": {
                "feature_class": ["someservice.FC2"],
                "objective": "someservice.CO2",
                "weighted_priority": "Medium",
            },
        },
        "control_objectives": {"someservice.CO1": {"scf": ["SCF1"]}},
    }

    expected_diff = {}

    assert apply_json_filter(original_json, filter_json) == expected_diff


def test_json_deletion():
    original_json = {
        "controls": {
            "someservice.C1": {
                "feature_class": ["someservice.FC1", "someservice.FC2"],
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            }
        },
        "control_objectives": {"someservice.CO1": {"scf": ["SCF1", "SCF2"]}},
    }

    # Remove one feature class and one SCF
    filter_json = {
        "controls": {
            "someservice.C1": {
                "feature_class": ["someservice.FC1"],  # removed someservice.FC2
                "objective": "someservice.CO1",
                "weighted_priority": "High",
            }
        },
        "control_objectives": {"someservice.CO1": {"scf": ["SCF1"]}},  # removed SCF2
    }

    expected_diff = {
        "controls": {"someservice.C1": {"feature_class": ["someservice.FC2"]}},
        "control_objectives": {"someservice.CO1": {"scf": ["SCF2"]}},
    }

    assert apply_json_filter(original_json, filter_json) == expected_diff
def test_extract_letters_and_number():
    assert extract_letters_and_number("someservice.FC1") == (1, 1, 1)
    assert extract_letters_and_number("someservice.T2") == (1, 2, 2)
    assert extract_letters_and_number("someservice.CO3") == (1, 3, 3)
    assert extract_letters_and_number("someservice.C4") == (1, 4, 4)
    assert extract_letters_and_number("someservice.A5") == (1, 5, 5)
    assert extract_letters_and_number("someservice.X6") == (1, float("inf"), 6)
    assert extract_letters_and_number("someservice.123") == (0, "someservice.123", 0)

def test_sort_by_id():
    strings = ["someservice.3", "someservice.1", "someservice.2"]
    assert sort_by_id(strings) == ["someservice.1", "someservice.2", "someservice.3"]

def test_sort_dict_by_id():
    data_dict = {
        "someservice.3": "value3",
        "someservice.1": "value1",
        "someservice.2": "value2",
    }
    expected = {
        "someservice.1": "value1",
        "someservice.2": "value2",
        "someservice.3": "value3",
    }
    assert sort_dict_by_id(data_dict) == expected

def test_sort_dict_list_by_id():
    data_dict_list = [
        {"id": "someservice.C3"},
        {"id": "someservice.C1"},
        {"id": "someservice.C2"},
    ]
    expected = [
        {"id": "someservice.C1"},
        {"id": "someservice.C2"},
        {"id": "someservice.C3"},
    ]
    assert sort_dict_list_by_id(data_dict_list, "id") == expected

def test_sort_list_by_id():
    list_of_lists = [
        ["someservice.C3", "other"],
        ["someservice.C1", "other"],
        ["someservice.C2", "other"],
    ]
    expected = [
        ["someservice.C1", "other"],
        ["someservice.C2", "other"],
        ["someservice.C3", "other"],
    ]
    assert sort_list_by_id(list_of_lists, 0) == expected

from tmxcaliber.lib.tools import apply_json_filter


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

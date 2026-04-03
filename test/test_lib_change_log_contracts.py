from tmxcaliber.lib.change_log import generate_change_log


def test_generate_change_log_added_removed_modified_and_md_is_stable():
    old_json = {
        "metadata": {"release": "1700000000", "name": "Old"},
        "threats": {
            "Svc.T1": {
                "name": "ThreatOne",
                "access": {"AND": ["perm.read"]},
                "cvss_score": 5.0,
                "cvss_severity": "Medium",
            }
        },
        "controls": {
            "Svc.C1": {
                "description": "C1",
                "weighted_priority": "High",
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T1", "something": 1}],
            }
        },
        "control_objectives": {"Svc.CO1": {"description": "CO1", "scf": ["SCF1"]}},
        "actions": {},
        "feature_classes": {},
        "scorecard": {},
    }

    new_json = {
        "metadata": {"release": "1700001000", "name": "New"},
        "threats": {
            "Svc.T1": {
                "name": "ThreatOneRenamed",
                "access": {"AND": ["perm.read", "perm.write"]},
                "cvss_score": 9.9,
                "cvss_severity": "High",
            },
            "Svc.T2": {
                "name": "ThreatTwo",
                "access": {"AND": ["perm.x"]},
                "cvss_score": 3.0,
                "cvss_severity": "Low",
            },
        },
        "controls": {
            "Svc.C1": {
                "description": "C1",
                "weighted_priority": "High",
                "feature_class": ["Svc.FC1"],
                "mitigate": [{"threat": "Svc.T1", "something": 2}],
            }
        },
        "control_objectives": {"Svc.CO1": {"description": "CO1", "scf": ["SCF2"]}},
        "actions": {},
        "feature_classes": {},
        "scorecard": {},
    }

    change_log = generate_change_log(old_json, new_json)

    json_out = change_log.get_json()
    assert json_out["release"]["old_epoch"] == "1700000000"
    assert json_out["release"]["new_epoch"] == "1700001000"
    assert json_out["release"]["old_utc"]
    assert json_out["release"]["new_utc"]

    md = change_log.get_md()
    assert "## Changes Summary" in md
    assert "## Changes" in md

    assert "Added Svc.T2" in md

    # Access is handled specially, and should appear as a modified sub-change.
    assert "Modified Svc.T1.access" in md

    # Field change produces a fenced code block in long MD.
    assert "```" in md
    assert "From:" in md
    assert "To:" in md

    # Ignored fields (e.g. threats.cvss_score) must not show up.
    assert "cvss_score" not in md
    assert "cvss_score" not in str(json_out)

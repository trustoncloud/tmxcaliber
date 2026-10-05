"""The severity scale is TrustOnCloud's own, and has one owner in the schema.

TrustOnCloud rates severity "Very High" through "Very Low". The scale is
CVSS-like, but it is not CVSS: there is no "Critical" rating. Seven published
ThreatModels nonetheless carry "Critical" in both their control and threat
sections, which went unnoticed because only one of the two sites constrained
the value and it constrained it to the wrong list.

These tests pin the scale itself and the fact that both sites read it from the
same place, so neither half of that can come back quietly.
"""

from __future__ import annotations

from typing import Any

from tmxcaliber.schema import schema as schema_mod

#: The scale, spelled out once here so a change to the schema has to be
#: deliberate enough to change a test that says why.
SCALE = ["Very High", "High", "Medium", "Low", "Very Low"]

CONTROL_PATTERN = r"^[A-Za-z0-9]+\.C[0-9]+$"
THREAT_PATTERN = r"^[A-Za-z0-9]+\.T[0-9]+$"
POINTER = "#/definitions/severityRating"


def _schema() -> dict[str, Any]:
    """Load the schema the validator actually selects.

    Returns:
        The latest threatmodel schema.
    """
    return schema_mod._load_schema("threatmodel")


def test_the_scale_is_trustoncloud_s_own() -> None:
    assert _schema()["definitions"]["severityRating"]["enum"] == SCALE


def test_critical_is_not_a_rating() -> None:
    # The value that leaked into seven models. CVSS has it; this scale
    # does not, and "Very High" is the rating those rows should carry.
    assert "Critical" not in _schema()["definitions"]["severityRating"]["enum"]


def test_both_sections_read_the_same_definition() -> None:
    """One owner, so the two sites cannot disagree.

    They did disagree: the control site carried an enum and the threat
    site carried none, so the same bad value was rejected in one place
    and accepted in the other.
    """
    schema = _schema()
    control = schema["properties"]["controls"]["patternProperties"][CONTROL_PATTERN][
        "properties"
    ]["mitigate"]["items"]["properties"]["cvss"]
    threat = schema["properties"]["threats"]["patternProperties"][THREAT_PATTERN][
        "properties"
    ]["cvss_severity"]

    assert control == {"$ref": POINTER}
    assert threat == {"$ref": POINTER}

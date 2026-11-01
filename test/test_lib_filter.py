import pytest

from tmxcaliber.lib.filter import Filter


def test_mitre_tactics_are_split_trimmed_and_lowercased():
    assert Filter(mitre_tactics="TA0010, ta0040").mitre_tactics == [
        "ta0010",
        "ta0040",
    ]


def test_mitre_tactics_default_to_none():
    assert Filter().mitre_tactics == []


@pytest.mark.parametrize("value", ["Exfiltration", "T1537", "TA10", "TA0010,T1537"])
def test_mitre_tactics_reject_anything_but_a_tactic_code(value):
    with pytest.raises(ValueError, match="Invalid MITRE tactic format"):
        Filter(mitre_tactics=value)


def test_mitre_tactics_ignore_a_blank_item():
    assert Filter(mitre_tactics="TA0010, ").mitre_tactics == ["ta0010"]

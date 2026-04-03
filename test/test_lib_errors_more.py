from tmxcaliber.lib.errors import (
    BinaryNotFound,
    FeatureClassCycleError,
    FrameworkNotFoundError,
)


def test_framework_not_found_error_exposes_user_friendly_message():
    error = FrameworkNotFoundError("ISO 27002")

    assert "ISO 27002" in str(error)
    assert "provided Excel file" in str(error)


def test_other_error_messages_are_preserved():
    assert "Cycle detected" in str(FeatureClassCycleError(["Svc.FC1", "Svc.FC2"]))
    assert str(BinaryNotFound("drawio missing")) == "drawio missing"

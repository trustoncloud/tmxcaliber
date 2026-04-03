import pytest
import unittest
import sys
from tmxcaliber.cli import (
    _get_version,
    get_params,
    validate,
    map,
    scan_controls,
    get_input_data,
    get_drawio_binary_path,
    output_result,
    get_metadata,
    get_service_rows,
    get_feature_class_rows,
    METADATA_MISSING,
    validate_and_get_framework,
    MISSING_OUTPUT_ERROR,
)
import json
import platform
import argparse
from argparse import Namespace

import csv
from tmxcaliber.lib.threatmodel_data import ThreatModelData
from tmxcaliber.lib.errors import BinaryNotFound

import pytest
from unittest.mock import mock_open, patch, MagicMock, call


@pytest.fixture
def mock_json_file(mock_json):
    return json.dumps(mock_json)


@pytest.fixture
def mock_json():
    return {
        "controls": {
            "someservice.C1": {
                "feature_class": ["someservice.FC1"],
                "objective": "someservice.co1",
                "weighted_priority": "High",
            }
        },
        "control_objectives": {"someservice.co1": {"scf": ["SCF1"]}},
        "threats": {},
        "actions": {},
        "feature_classes": {},
    }


@pytest.fixture
def mock_invalid_json():
    return "this is not json"


def test_get_version():
    version = _get_version()
    assert isinstance(version, str)
    assert version.startswith("tmxcaliber")


@pytest.fixture
def mock_argv(mocker):
    # Mock sys.argv for the duration of the test
    args = [
        "filter",
        "--severity",
        "high",
        "--events",
        "login",
        "--permissions",
        "read",
        "--ids",
        "someservice.co123,someservice.C134,someservice.co456,someservice.C123,someservice.fc123,someservice.fc456,someservice.t123,someservice.t223",
    ]
    mocker.patch("sys.argv", ["test_program"] + args)


def test_validate(mock_argv):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation")
    filter_parser = subparsers.add_parser("filter")
    filter_parser.add_argument("--severity")
    filter_parser.add_argument("--events")
    filter_parser.add_argument("--permissions")
    filter_parser.add_argument("--ids")
    filter_parser.add_argument("--output-removed")
    validated_args = validate(parser)
    assert validated_args.filter_obj.severity == "high"
    assert "login" in validated_args.filter_obj.events
    assert "read" in validated_args.filter_obj.permissions
    assert validated_args.filter_obj.feature_classes == [
        "someservice.fc123",
        "someservice.fc456",
    ]
    assert validated_args.filter_obj.controls == [
        "someservice.c134",
        "someservice.c123",
    ]
    assert validated_args.filter_obj.control_objectives == [
        "someservice.co123",
        "someservice.co456",
    ]
    assert validated_args.filter_obj.threats == ["someservice.t123", "someservice.t223"]
    assert validated_args.filter_obj.ids == [
        "someservice.co123",
        "someservice.c134",
        "someservice.co456",
        "someservice.c123",
        "someservice.fc123",
        "someservice.fc456",
        "someservice.t123",
        "someservice.t223",
    ]


def test_validate_requires_output_with_output_removed():
    # Create a parser instance and configure it as it would be in your application
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation")
    filter_parser = subparsers.add_parser("filter")
    filter_parser.add_argument("--output-removed", action="store_true")
    filter_parser.add_argument("--output", type=str)

    # Mock parse_args to return specific configurations
    args = Namespace(operation="filter", output_removed=True, output=None)
    parser.parse_args = MagicMock(
        return_value=args
    )  # Mock parse_args to return the mocked args

    # Test that the parser.error is called with the correct message when conditions are met
    with pytest.raises(SystemExit):  # parser.error calls sys.exit
        validate(parser)

    # You should also check that the error message is correct. For this, you might need to further mock parser.error
    parser.error = MagicMock()
    validate(parser)
    parser.error.assert_called_once_with(MISSING_OUTPUT_ERROR)


def test_map(mock_json):
    framework2co = [
        ("SCF1", "FrameworkControl1"),
        ("SCF1", "FrameworkControl2"),
        ("SCF2", ""),
    ]
    threatmodel_data = ThreatModelData(mock_json)
    metadata = {"FrameworkControl1": {"additional_info": "info"}}
    result = map(
        framework2co, threatmodel_data, "Framework", ["additional_info"], metadata
    )
    expected_result = {
        "FrameworkControl1": {
            "control_objectives": ["someservice.co1"],
            "scf": ["SCF1"],
            "controls": {
                "Very High": [],
                "High": ["someservice.C1"],
                "Medium": [],
                "Low": [],
                "Very Low": [],
            },
            "additional_info": "info",
        },
        "FrameworkControl2": {
            "control_objectives": ["someservice.co1"],
            "scf": ["SCF1"],
            "controls": {
                "Very High": [],
                "High": ["someservice.C1"],
                "Medium": [],
                "Low": [],
                "Very Low": [],
            },
            "additional_info": METADATA_MISSING,
        },
    }
    assert result == expected_result


def test_scan_controls():
    args = Namespace(pattern="UnauthorizedAccess")
    data = {"controls": {"1": {"description": "Unauthorized access detected"}}}
    result = scan_controls(args, data)
    assert result["controls"] == {}
    data = {
        "controls": {
            "1": {"description": "Unauthorized access detected UnauthorizedAccess"}
        }
    }
    result = scan_controls(args, data)
    assert "1" in result["controls"]


def test_get_input_data_valid_sources(mock_json_file, mock_json):
    args = Namespace(
        new_source="valid_new_source.json",
        old_source="valid_old_source.json",
        operation="create_change_log",
    )

    with patch("builtins.open", mock_open(read_data=mock_json_file)), patch(
        "os.path.isfile", return_value=True
    ), patch("os.path.isdir", return_value=False), patch(
        "os.path.exists", return_value=True
    ):

        result = get_input_data(args)

        assert isinstance(result, dict)
        assert "new_source" in result
        assert "old_source" in result
        assert len(result["new_source"]) == 1
        assert isinstance(result["new_source"][0], ThreatModelData)
        assert result["new_source"][0].threatmodel_json == mock_json
        assert len(result["old_source"]) == 1
        assert isinstance(result["old_source"][0], ThreatModelData)
        assert result["old_source"][0].threatmodel_json == mock_json


def test_get_input_data_invalid_json_new_source(mock_invalid_json):
    args = Namespace(
        new_source="invalid_new_source.json",
        old_source="valid_old_source.json",
        operation="create_change_log",
    )

    with patch("builtins.open", mock_open(read_data=mock_invalid_json)), patch(
        "os.path.isfile", return_value=True
    ), patch("os.path.isdir", return_value=False), patch(
        "os.path.exists", return_value=True
    ):
        with pytest.raises(SystemExit):
            get_input_data(args)


def test_get_input_data_invalid_json_old_source(mock_invalid_json):
    args = Namespace(
        new_source="valid_new_source.json",
        old_source="invalid_old_source.json",
        operation="create_change_log",
    )

    with patch("builtins.open", mock_open(read_data=mock_invalid_json)), patch(
        "os.path.isfile", return_value=True
    ), patch("os.path.isdir", return_value=False), patch(
        "os.path.exists", return_value=True
    ):
        with pytest.raises(SystemExit):
            get_input_data(args)


def test_get_input_data_nonexistent_new_source():
    args = Namespace(
        new_source="nonexistent_new_source.json",
        old_source="valid_old_source.json",
        operation="create_change_log",
    )

    with patch("os.path.exists", return_value=False):
        with pytest.raises(SystemExit):
            get_input_data(args)


def test_get_input_data_nonexistent_old_source():
    args = Namespace(
        new_source="valid_new_source.json",
        old_source="nonexistent_old_source.json",
        operation="create_change_log",
    )

    with patch("os.path.exists", return_value=False):
        with pytest.raises(SystemExit):
            get_input_data(args)


def test_get_input_data_valid_json_source(mock_json_file, mock_json):
    args = Namespace(source="validpath.json", operation="list")

    with patch("builtins.open", mock_open(read_data=mock_json_file)), patch(
        "os.path.isfile", return_value=True
    ), patch("os.path.isdir", return_value=False), patch(
        "os.path.exists", return_value=True
    ):

        result = get_input_data(args)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], ThreatModelData)
        assert result[0].threatmodel_json == mock_json


def test_get_input_data_invalid_json_source(mock_invalid_json):
    args = Namespace(source="invalidpath.json", operation="list")

    with patch("builtins.open", mock_open(read_data=mock_invalid_json)), patch(
        "os.path.isfile", return_value=True
    ), patch("os.path.isdir", return_value=False), patch(
        "os.path.exists", return_value=True
    ):
        with pytest.raises(SystemExit):
            get_input_data(args)


def test_get_input_data_nonexistent_file_source():
    args = Namespace(source="nonexistent.json", operation="list")

    with patch("os.path.exists", return_value=False):
        with pytest.raises(SystemExit):
            get_input_data(args)


def test_get_input_data_valid_json(mock_json_file, mock_json):
    args = Namespace(source="validpath.json", operation="list")

    with patch("builtins.open", mock_open(read_data=mock_json_file)), patch(
        "os.path.isfile", return_value=True
    ), patch("os.path.isdir", return_value=False), patch(
        "os.path.exists", return_value=True
    ):

        result = get_input_data(args)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], ThreatModelData)
        assert result[0].threatmodel_json == mock_json


def test_get_drawio_binary_path_windows(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    potential_paths = [
        r"C:\Program Files\draw.io\draw.io.exe",
        r"C:\Program Files (x86)\draw.io\draw.io.exe",
    ]
    with unittest.mock.patch("os.path.isfile", return_value=True) as isfile_mock:
        path = get_drawio_binary_path()
        isfile_mock.assert_any_call(potential_paths[0])  # Ensure first path is checked
        assert path in potential_paths  # Ensure one of the potential paths is returned


def test_get_drawio_binary_path_linux(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    with unittest.mock.patch("os.path.isfile", return_value=False):
        path = get_drawio_binary_path()
        assert path == "xvfb-run -a drawio"


def test_get_drawio_binary_path_macos(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    potential_path = "/Applications/draw.io.app/Contents/MacOS/draw.io"
    with unittest.mock.patch("os.path.isfile", return_value=True) as isfile_mock:
        path = get_drawio_binary_path()
        isfile_mock.assert_called_once_with(
            potential_path
        )  # Ensure macOS path is checked
        assert path == potential_path


def test_get_drawio_binary_path_not_found(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Unknown")
    with pytest.raises(BinaryNotFound):
        get_drawio_binary_path()


def test_get_params_list_services_defaults(tmp_path, monkeypatch):
    source = tmp_path / "services"
    source.mkdir()

    monkeypatch.setattr(sys, "argv", ["prog", "list", "services", str(source)])

    params = get_params()

    assert params.operation == "list"
    assert params.list_type == "services"
    assert params.format == "csv"


def test_get_params_list_services_accepts_json_format(tmp_path, monkeypatch):
    source = tmp_path / "services"
    source.mkdir()

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "services", str(source), "--format", "json"],
    )

    params = get_params()

    assert params.operation == "list"
    assert params.list_type == "services"
    assert params.format == "json"


def test_get_params_list_feature_classes_defaults(tmp_path, monkeypatch):
    source = tmp_path / "service.json"
    source.write_text(json.dumps({"feature_classes": {}}), encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["prog", "list", "feature-classes", str(source)])

    params = get_params()

    assert params.operation == "list"
    assert params.list_type == "feature-classes"
    assert params.format == "csv"


def test_get_params_list_feature_classes_accepts_json_format(tmp_path, monkeypatch):
    source = tmp_path / "service.json"
    source.write_text(json.dumps({"feature_classes": {}}), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "feature-classes", str(source), "--format", "json"],
    )

    params = get_params()

    assert params.operation == "list"
    assert params.list_type == "feature-classes"
    assert params.format == "json"


def test_output_json_result():
    output_param = "output.json"
    result = {"key": "value"}
    result_type = "json"
    m = mock_open()
    with patch("builtins.open", m):
        output_result(output_param, result, result_type)
    m.assert_called_once_with(output_param, "w+", newline="")
    handle = m()
    handle.write.assert_called_once_with(json.dumps(result, indent=2))
    assert handle.write.call_args[0][0] == json.dumps(result, indent=2)


def test_output_csv_result():
    output_param = "output.csv"
    result = [["header1", "header2"], ["data1", "data2"]]
    result_type = "csv_list"
    m = mock_open()
    with patch("builtins.open", m):
        with patch("csv.writer", MagicMock()) as mock_csv_writer:
            output_result(output_param, result, result_type)
    # Verify the file was opened with the correct parameters
    m.assert_called_once_with(output_param, mode="w", newline="", encoding="utf-8")
    # Now also check the csv.writer was called correctly, including the additional parameters
    handle = m()
    mock_csv_writer.assert_called_once_with(
        handle, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
    )
    # Check calls to writerow method on the mock csv_writer
    calls = [call(line) for line in result]
    mock_csv_writer().writerow.assert_has_calls(calls, any_order=True)


def test_get_input_data_multiple_files():
    args = Namespace(source="validpath", operation="list")
    with pytest.raises(SystemExit):
        get_input_data(args)


def test_output_result_unsupported_type():
    with pytest.raises(TypeError):
        output_result(None, None, "unsupported_type")


def test_get_metadata_with_complex_csv():
    # Mock data to simulate CSV content with commas and missing values
    csv_content = """id,any title 1,"any title_2, including support for commas"
        MY_CONTROL_1,My control 1,"Description 1, including support for commas"
        MY_CONTROL_2,My control 2,Description 2
        MY_CONTROL_3,My control 3,
        MY_CONTROL_4,,Description 4
        MY_CONTROL_5,My control 5,Description 5"""

    # Create a MagicMock for csv.DictReader
    mock_csv_reader = MagicMock()
    # Configure the MagicMock to mimic DictReader behavior
    mock_csv_reader.fieldnames = [
        "id",
        "any title 1",
        "any title_2, including support for commas",
    ]
    mock_csv_reader.__iter__.return_value = iter(
        [
            {
                "id": "MY_CONTROL_1",
                "any title 1": "My control 1",
                "any title_2, including support for commas": "Description 1, including support for commas",
            },
            {
                "id": "MY_CONTROL_2",
                "any title 1": "My control 2",
                "any title_2, including support for commas": "Description 2",
            },
            {
                "id": "MY_CONTROL_3",
                "any title 1": "My control 3",
                "any title_2, including support for commas": "",
            },
            {
                "id": "MY_CONTROL_4",
                "any title 1": "",
                "any title_2, including support for commas": "Description 4",
            },
            {
                "id": "MY_CONTROL_5",
                "any title 1": "My control 5",
                "any title_2, including support for commas": "Description 5",
            },
        ]
    )

    # Patch the open function and csv.DictReader in the module where they are used
    with patch("builtins.open", mock_open(read_data=csv_content)) as mocked_file:
        with patch("csv.DictReader", return_value=mock_csv_reader):
            fields, result = get_metadata("dummy_path.csv")

    # Assertions to verify the output
    assert fields == [
        "any title 1",
        "any title_2, including support for commas",
    ], "Field names beyond the first column are incorrect"
    assert result == {
        "MY_CONTROL_1": {
            "any title 1": "My control 1",
            "any title_2, including support for commas": "Description 1, including support for commas",
        },
        "MY_CONTROL_2": {
            "any title 1": "My control 2",
            "any title_2, including support for commas": "Description 2",
        },
        "MY_CONTROL_3": {
            "any title 1": "My control 3",
            "any title_2, including support for commas": "",
        },
        "MY_CONTROL_4": {
            "any title 1": "",
            "any title_2, including support for commas": "Description 4",
        },
        "MY_CONTROL_5": {
            "any title 1": "My control 5",
            "any title_2, including support for commas": "Description 5",
        },
    }, "Dictionary data does not match expected values"


def test_validate_and_get_framework_success_multiline(tmp_path):
    csv_path = tmp_path / "framework.csv"
    csv_path.write_text(
        "scf1;scf2,framework1;framework2\n"
        "scf4;scf2,framework8;framework2\n"
        "scf3,framework3\n",
        encoding="utf-8",
    )

    result = validate_and_get_framework(str(csv_path), "Framework")

    assert result == [
        ("scf1", "framework1"),
        ("scf1", "framework2"),
        ("scf2", "framework1"),
        ("scf2", "framework2"),
        ("scf4", "framework8"),
        ("scf4", "framework2"),
        ("scf2", "framework8"),
        ("scf3", "framework3"),
    ]


def test_validate_and_get_framework_missing_entries(tmp_path):
    csv_path = tmp_path / "framework.csv"
    csv_path.write_text(
        "scf1;scf2,\n" ",framework1;framework2\n" ",framework4\n" "scf3,framework3\n",
        encoding="utf-8",
    )

    result = validate_and_get_framework(str(csv_path), "Framework")

    assert result == [("scf3", "framework3")]


def test_validate_and_get_framework_dedupes_and_skips_none_like_values(tmp_path):
    csv_path = tmp_path / "framework.csv"
    csv_path.write_text(
        "scf1;None,framework1;framework2\n"
        "scf1,framework1\n"
        "null,framework9\n"
        "scf2,n/a\n",
        encoding="utf-8",
    )

    result = validate_and_get_framework(str(csv_path), "Framework")

    assert result == [
        ("scf1", "framework1"),
        ("scf1", "framework2"),
    ]


def test_validate_and_get_framework_failure_column_mismatch(tmp_path):
    csv_path = tmp_path / "framework.csv"
    csv_path.write_text("only_one_column\n", encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        validate_and_get_framework(str(csv_path), "Framework")

    assert "should have exactly 2 columns" in str(exc_info.value)


def test_validate_and_get_framework_file_not_found():
    with pytest.raises(FileNotFoundError) as exc_info:
        validate_and_get_framework("nonexistent_path.csv", "Framework")

    assert "No such file or directory" in str(exc_info.value)


def test_get_service_rows_recursive_directory_dedupes_and_skips_blank_names(tmp_path):
    top_level = tmp_path / "b.json"
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    nested = nested_dir / "a.json"
    ignored = tmp_path / "ignored.json"

    top_level.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "Primary Service",
                    "other_covered_services": [
                        "Covered One",
                        "Covered One",
                        "",
                        "  Covered Two  ",
                        "Primary Service",
                        None,
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    nested.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "   ",
                    "other_covered_services": ["Nested Covered", "", "Nested Covered"],
                }
            }
        ),
        encoding="utf-8",
    )
    ignored.write_text(json.dumps({"metadata": {"service_name": ""}}), encoding="utf-8")

    rows = get_service_rows(str(tmp_path))

    assert rows == [
        {"name": "Primary Service", "file": str(top_level.resolve())},
        {"name": "Covered One", "file": str(top_level.resolve())},
        {"name": "Covered Two", "file": str(top_level.resolve())},
        {"name": "Nested Covered", "file": str(nested.resolve())},
    ]


def test_get_service_rows_single_file(tmp_path):
    source = tmp_path / "service.json"
    source.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "Single Service",
                    "other_covered_services": [],
                }
            }
        ),
        encoding="utf-8",
    )

    rows = get_service_rows(str(source))

    assert rows == [{"name": "Single Service", "file": str(source.resolve())}]


def test_get_feature_class_rows_returns_id_name_description(tmp_path):
    source = tmp_path / "service.json"
    source.write_text(
        json.dumps(
            {
                "feature_classes": {
                    "Svc.FC1": {"name": "Primary FC", "description": "First feature"},
                    "Svc.FC2": {
                        "name": "Secondary FC",
                        "description": "Second feature",
                        "ignored": "value",
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    rows = get_feature_class_rows(str(source))

    assert rows == [
        {"id": "Svc.FC1", "name": "Primary FC", "description": "First feature"},
        {"id": "Svc.FC2", "name": "Secondary FC", "description": "Second feature"},
    ]


def test_get_feature_class_rows_uses_blank_defaults_for_missing_values(tmp_path):
    source = tmp_path / "service.json"
    source.write_text(
        json.dumps(
            {
                "feature_classes": {
                    "Svc.FC1": {"name": "Primary FC"},
                    "Svc.FC2": {"description": "Only description"},
                    "Svc.FC3": "invalid",
                }
            }
        ),
        encoding="utf-8",
    )

    rows = get_feature_class_rows(str(source))

    assert rows == [
        {"id": "Svc.FC1", "name": "Primary FC", "description": ""},
        {"id": "Svc.FC2", "name": "", "description": "Only description"},
        {"id": "Svc.FC3", "name": "", "description": ""},
    ]


def test_main_list_controls_aws_data_perimeter_e2e(tmp_path, monkeypatch, capsys):
    from tmxcaliber import cli as cli_module
    from tmxcaliber.lib.threatmodel_data import ThreatModelData

    ThreatModelData.threatmodel_data_list = []

    tm1 = {
        "metadata": {"release": "1710000000", "name": "TM1"},
        "controls": {
            "Svc.C2": {"objective": "Svc.CO1", "retired": False},
            "Svc.C10": {"objective": "Svc.CO1", "retired": False},
        },
        "control_objectives": {"Svc.CO1": {"description": "Objective 1"}},
        "scorecard": {"aws_data_perimeter": {"Perimeter": ["Svc.C10", "Svc.C2"]}},
        "threats": {},
        "actions": {},
        "feature_classes": {},
    }
    tm2 = {
        "metadata": {"release": "1710000001", "name": "TM2"},
        "controls": {"Svc.C1": {"objective": "Svc.CO2", "retired": False}},
        "control_objectives": {"Svc.CO2": {"description": "Objective 2"}},
        "scorecard": {"aws_data_perimeter": {"NA": ["Svc.C1"], "Other": ["Svc.C1"]}},
        "threats": {},
        "actions": {},
        "feature_classes": {},
    }

    (tmp_path / "tm1.json").write_text(json.dumps(tm1), encoding="utf-8")
    (tmp_path / "tm2.json").write_text(json.dumps(tm2), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "controls", str(tmp_path), "--type", "AWS_DATA_PERIMETER"],
    )

    cli_module.main()
    out = capsys.readouterr().out.strip().splitlines()

    assert out[0] == "objective,objective_description,id,retired"

    # Output is emitted TM-by-TM (directory load order), with numeric ordering within each TM.
    assert out[1:] == [
        "Svc.CO1,Objective 1,Svc.C2,False",
        "Svc.CO1,Objective 1,Svc.C10,False",
        "Svc.CO2,Objective 2,Svc.C1,False",
    ]


def test_main_list_services_csv_e2e(tmp_path, monkeypatch, capsys):
    from tmxcaliber import cli as cli_module

    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()

    first = tmp_path / "a.json"
    second = nested_dir / "b.json"

    first.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "Alpha Service",
                    "other_covered_services": ["Alpha Addon"],
                }
            }
        ),
        encoding="utf-8",
    )
    second.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "Beta Service",
                    "other_covered_services": [],
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(sys, "argv", ["prog", "list", "services", str(tmp_path)])

    cli_module.main()
    out = capsys.readouterr().out.strip().splitlines()

    assert out == [
        "name,file",
        f"Alpha Service,{first.resolve()}",
        f"Alpha Addon,{first.resolve()}",
        f"Beta Service,{second.resolve()}",
    ]


def test_main_list_services_json_e2e_preserves_duplicate_names_across_files(
    tmp_path, monkeypatch, capsys
):
    from tmxcaliber import cli as cli_module

    first = tmp_path / "a.json"
    second = tmp_path / "b.json"

    first.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "Shared Service",
                    "other_covered_services": ["Addon One"],
                }
            }
        ),
        encoding="utf-8",
    )
    second.write_text(
        json.dumps(
            {
                "metadata": {
                    "service_name": "Shared Service",
                    "other_covered_services": [],
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "services", str(tmp_path), "--format", "json"],
    )

    cli_module.main()
    out = json.loads(capsys.readouterr().out)

    assert out == [
        {"name": "Shared Service", "file": str(first.resolve())},
        {"name": "Addon One", "file": str(first.resolve())},
        {"name": "Shared Service", "file": str(second.resolve())},
    ]


def test_main_list_feature_classes_csv_e2e(tmp_path, monkeypatch, capsys):
    from tmxcaliber import cli as cli_module

    source = tmp_path / "service.json"
    source.write_text(
        json.dumps(
            {
                "feature_classes": {
                    "Svc.FC1": {"name": "Primary FC", "description": "First feature"},
                    "Svc.FC2": {
                        "name": "Secondary FC",
                        "description": "Second feature",
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(sys, "argv", ["prog", "list", "feature-classes", str(source)])

    cli_module.main()
    out = capsys.readouterr().out.strip().splitlines()

    assert out == [
        "id,name,description",
        "Svc.FC1,Primary FC,First feature",
        "Svc.FC2,Secondary FC,Second feature",
    ]


def test_main_list_feature_classes_json_e2e(tmp_path, monkeypatch, capsys):
    from tmxcaliber import cli as cli_module

    source = tmp_path / "service.json"
    source.write_text(
        json.dumps(
            {
                "feature_classes": {
                    "Svc.FC1": {"name": "Primary FC", "description": "First feature"},
                    "Svc.FC2": {"name": "Secondary FC"},
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "feature-classes", str(source), "--format", "json"],
    )

    cli_module.main()
    out = json.loads(capsys.readouterr().out)

    assert out == [
        {"id": "Svc.FC1", "name": "Primary FC", "description": "First feature"},
        {"id": "Svc.FC2", "name": "Secondary FC", "description": ""},
    ]


def test_main_filter_output_removed_writes_two_files(tmp_path, monkeypatch):
    from tmxcaliber import cli as cli_module
    from tmxcaliber.lib.threatmodel_data import ThreatModelData

    ThreatModelData.threatmodel_data_list = []

    source = tmp_path / "source.json"
    out = tmp_path / "out.json"

    tm = {
        "metadata": {"release": "1710000000", "name": "TM"},
        "feature_classes": {
            "Svc.FC1": {"class_relationship": []},
            "Svc.FC2": {"class_relationship": [{"type": "parent", "class": "Svc.FC1"}]},
            "Svc.FC3": {"class_relationship": []},
        },
        "threats": {
            "Svc.T1": {
                "feature_class": "Svc.FC2",
                "cvss_severity": "High",
                "name": "Threat1",
                "access": {"AND": ["perm.read"]},
            },
            "Svc.T2": {
                "feature_class": "Svc.FC3",
                "cvss_severity": "Low",
                "name": "Threat2",
                "access": {"AND": ["perm.write"]},
            },
        },
        "control_objectives": {
            "Svc.CO1": {"description": "CO1"},
            "Svc.CO2": {"description": "CO2"},
        },
        "controls": {
            "Svc.C1": {
                "feature_class": ["Svc.FC2", "Svc.FC3"],
                "objective": "Svc.CO1",
                "coso": "Prevent",
                "description": "C1",
                "weighted_priority": "High",
                "assured_by": "",
                "mitigate": [{"threat": "Svc.T1"}, {"threat": "Svc.T2"}],
            },
            "Svc.C2": {
                "feature_class": ["Svc.FC3"],
                "objective": "Svc.CO2",
                "coso": "Prevent",
                "description": "C2",
                "weighted_priority": "Low",
                "assured_by": "",
                "mitigate": [{"threat": "Svc.T2"}],
            },
        },
        "actions": {
            "Svc.A1": {"feature_class": "Svc.FC2"},
            "Svc.A2": {"feature_class": "Svc.FC3"},
        },
    }

    source.write_text(json.dumps(tm), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "filter",
            "--output",
            str(out),
            "--output-removed",
            "--severity",
            "high",
            str(source),
        ],
    )

    cli_module.main()

    assert out.exists()
    out_json = json.loads(out.read_text(encoding="utf-8"))
    assert "threats" in out_json
    assert list(out_json["threats"].keys()) == ["Svc.T1"]

    removed_path = tmp_path / "out_removed.json"
    assert removed_path.exists()
    removed_json = json.loads(removed_path.read_text(encoding="utf-8"))

    # At minimum, the removed output should include removed threats/controls.
    assert "threats" in removed_json
    assert "Svc.T2" in removed_json["threats"] or "Svc.T2" in str(removed_json)

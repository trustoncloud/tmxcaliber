import pytest
from tmxcaliber.cli import _get_version, is_file_or_dir, validate, map, scan_controls, get_input_data, get_drawio_binary_path, output_result, get_metadata, METADATA_MISSING, validate_and_get_framework, MISSING_OUTPUT_ERROR
import json
import os
import argparse
import pandas as pd
from argparse import Namespace
from pandas.testing import assert_frame_equal

import csv
from tmxcaliber.lib.threatmodel_data import ThreatModelData
from tmxcaliber.cli import BinaryNotFound, ArgumentTypeError

import pytest
from unittest.mock import mock_open, patch, MagicMock, call

@pytest.fixture
def mock_json_file(mock_json):
    return json.dumps(mock_json)

@pytest.fixture
def mock_json():
    return {'controls': {'someservice.C1': {
      "feature_class": ["someservice.FC1"],
      "objective": 'someservice.CO1',
      "weighted_priority": "High"}}, 'control_objectives': {'someservice.CO1':{'scf':['SCF1']}}, 'threats': {}, 'actions': {}, 'feature_classes': {}} 

def test_get_version():
    version = _get_version()
    assert isinstance(version, str)
    assert version.startswith('tmxcaliber')

def test_is_file_or_dir():
    with pytest.raises(ArgumentTypeError, match="The path nonexistentpath.json does not exist"):
        is_file_or_dir("nonexistentpath.json")
    assert is_file_or_dir("existingfile.json") == "existingfile.json"
    assert is_file_or_dir("existingdir") == "existingdir"

@pytest.fixture
def mock_argv(mocker):
    # Mock sys.argv for the duration of the test
    args = [
        'filter',
        '--severity', 'high',
        '--events', 'login',
        '--permissions', 'read',
        '--ids', 'someservice.CO123,someservice.C134,someservice.CO456,someservice.C123,SOMESERVICE.FC123,SOMESERVICE.FC456,someservice.T123,someservice.T223',
    ]
    mocker.patch('sys.argv', ['test_program'] + args)

def test_validate(mock_argv):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='operation')
    filter_parser = subparsers.add_parser('filter')
    filter_parser.add_argument('--severity')
    filter_parser.add_argument('--events')
    filter_parser.add_argument('--permissions')
    filter_parser.add_argument('--ids')
    filter_parser.add_argument('--output-removed')
    validated_args = validate(parser)
    assert validated_args.filter_obj.severity == 'high'
    assert 'login' in validated_args.filter_obj.events
    assert 'read' in validated_args.filter_obj.permissions
    assert validated_args.filter_obj.feature_classes == ['SOMESERVICE.FC123','SOMESERVICE.FC456']
    assert validated_args.filter_obj.controls == ['SOMESERVICE.C134','SOMESERVICE.C123']
    assert validated_args.filter_obj.control_objectives == ['SOMESERVICE.CO123','SOMESERVICE.CO456']
    assert validated_args.filter_obj.threats == ['SOMESERVICE.T123','SOMESERVICE.T223']
    assert validated_args.filter_obj.ids == ['SOMESERVICE.CO123','SOMESERVICE.C134','SOMESERVICE.CO456','SOMESERVICE.C123','SOMESERVICE.FC123','SOMESERVICE.FC456','SOMESERVICE.T123','SOMESERVICE.T223']

def test_validate_requires_output_with_output_removed():
    # Create a parser instance and configure it as it would be in your application
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='operation')
    filter_parser = subparsers.add_parser('filter')
    filter_parser.add_argument('--output-removed', action='store_true')
    filter_parser.add_argument('--output', type=str)

    # Mock parse_args to return specific configurations
    args = Namespace(operation='filter', output_removed=True, output=None)
    parser.parse_args = MagicMock(return_value=args)  # Mock parse_args to return the mocked args

    # Test that the parser.error is called with the correct message when conditions are met
    with pytest.raises(SystemExit):  # parser.error calls sys.exit
        validate(parser)

    # You should also check that the error message is correct. For this, you might need to further mock parser.error
    parser.error = MagicMock()
    validate(parser)
    parser.error.assert_called_once_with(MISSING_OUTPUT_ERROR)

def test_map(mock_json):
    framework2co = pd.DataFrame({'SCF': ['SCF1', 'SCF1', 'SCF2'], 'Framework': ['FrameworkControl1', 'FrameworkControl2', '']})
    threatmodel_data = ThreatModelData(mock_json)
    metadata = {'FrameworkControl1': {'additional_info': 'info'}}
    result = map(framework2co, threatmodel_data, 'Framework', ['additional_info'], metadata)
    expected_result = {
        'FrameworkControl1': {
            'control_objectives': ['someservice.CO1'],
            'scf': ['SCF1'],
            'controls': {
                'Very High': [],
                'High': ['someservice.C1'],
                'Medium': [],
                'Low': [],
                'Very Low': []
            },
            'additional_info': 'info'
        },
        'FrameworkControl2': {
            'control_objectives': ['someservice.CO1'],
            'scf': ['SCF1'],
            'controls': {
                'Very High': [],
                'High': ['someservice.C1'],
                'Medium': [],
                'Low': [],
                'Very Low': []
            },
            'additional_info': METADATA_MISSING
        }
    }
    assert result == expected_result

def test_scan_controls():
    args = Namespace(pattern='UnauthorizedAccess')
    data = {'controls': {'1': {'description': 'Unauthorized access detected'}}}
    result = scan_controls(args, data)
    assert result['controls'] == {}
    data = {'controls': {'1': {'description': 'Unauthorized access detected UnauthorizedAccess'}}}
    result = scan_controls(args, data)
    assert '1' in result['controls']

def test_get_input_data_valid_json(mock_json_file, mock_json):
    args = Namespace(source='validpath.json', operation='list')
    with patch('builtins.open', mock_open(read_data=mock_json_file)), \
         patch('os.path.isfile', return_value=True), \
         patch('os.path.isdir', return_value=False):
        result = get_input_data(args)
        assert isinstance(result, list)
        assert result[0].threatmodel_json == mock_json

def test_get_input_data_invalid_json():
    args = Namespace(source='invalidpath.json', operation='list')
    with patch('builtins.open', mock_open(read_data='this is not json')), \
         patch('os.path.isfile', return_value=True), \
         patch('os.path.isdir', return_value=False):
        with pytest.raises(SystemExit):
            get_input_data(args)

def test_get_input_data_nonexistent_file():
    args = Namespace(source='nonexistent.json', operation='list')
    with patch('os.path.isfile', return_value=False), \
         patch('os.path.isdir', return_value=False):
        with pytest.raises(SystemExit):
            get_input_data(args)

def test_get_drawio_binary_path():
    path = get_drawio_binary_path()
    assert os.path.exists(path)

def test_output_json_result():
    output_param = 'output.json'
    result = {'key': 'value'}
    result_type = 'json'
    m = mock_open()
    with patch('builtins.open', m):
        output_result(output_param, result, result_type)
    m.assert_called_once_with(output_param, 'w+', newline='')
    handle = m()
    handle.write.assert_called_once_with(json.dumps(result, indent=2))
    assert handle.write.call_args[0][0] == json.dumps(result, indent=2)

def test_output_csv_result():
    output_param = 'output.csv'
    result = [['header1', 'header2'], ['data1', 'data2']]
    result_type = 'csv_list'
    m = mock_open()
    with patch('builtins.open', m):
        with patch('csv.writer', MagicMock()) as mock_csv_writer:
            output_result(output_param, result, result_type)
    # Verify the file was opened with the correct parameters
    m.assert_called_once_with(output_param, mode='w', newline='', encoding='utf-8')
    # Now also check the csv.writer was called correctly, including the additional parameters
    handle = m()
    mock_csv_writer.assert_called_once_with(handle, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    # Check calls to writerow method on the mock csv_writer
    calls = [call(line) for line in result]
    mock_csv_writer().writerow.assert_has_calls(calls, any_order=True)

def test_is_file_or_dir():
    with pytest.raises(ArgumentTypeError, match="The path nonexistentpath.json does not exist"):
        is_file_or_dir("nonexistentpath.json")

def test_is_file_or_dir_invalid_file_type():
    with patch('os.path.exists', return_value=True), \
         patch('os.path.isfile', return_value=True), \
         patch('os.path.isdir', return_value=False), \
         pytest.raises(ArgumentTypeError, match="The file invalidfiletype.txt is not valid, only json or xml can be given."):
        is_file_or_dir("invalidfiletype.txt")

def test_get_input_data_multiple_files():
    args = Namespace(source='validpath', operation='list')
    with pytest.raises(SystemExit):
        get_input_data(args)

def test_get_drawio_binary_path_not_found():
    with patch('os.path.isfile', return_value=False), \
         pytest.raises(BinaryNotFound):
        get_drawio_binary_path()
        get_drawio_binary_path()

def test_output_result_unsupported_type():
    with pytest.raises(TypeError):
        output_result(None, None, 'unsupported_type')

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
    mock_csv_reader.fieldnames = ['id', 'any title 1', 'any title_2, including support for commas']
    mock_csv_reader.__iter__.return_value = iter([
        {'id': 'MY_CONTROL_1', 'any title 1': 'My control 1', 'any title_2, including support for commas': 'Description 1, including support for commas'},
        {'id': 'MY_CONTROL_2', 'any title 1': 'My control 2', 'any title_2, including support for commas': 'Description 2'},
        {'id': 'MY_CONTROL_3', 'any title 1': 'My control 3', 'any title_2, including support for commas': ''},
        {'id': 'MY_CONTROL_4', 'any title 1': '', 'any title_2, including support for commas': 'Description 4'},
        {'id': 'MY_CONTROL_5', 'any title 1': 'My control 5', 'any title_2, including support for commas': 'Description 5'}
    ])

    # Patch the open function and csv.DictReader in the module where they are used
    with patch('builtins.open', mock_open(read_data=csv_content)) as mocked_file:
        with patch('csv.DictReader', return_value=mock_csv_reader):
            fields, result = get_metadata('dummy_path.csv')

    # Assertions to verify the output
    assert fields == ['any title 1', 'any title_2, including support for commas'], "Field names beyond the first column are incorrect"
    assert result == {
        'MY_CONTROL_1': {'any title 1': 'My control 1', 'any title_2, including support for commas': 'Description 1, including support for commas'},
        'MY_CONTROL_2': {'any title 1': 'My control 2', 'any title_2, including support for commas': 'Description 2'},
        'MY_CONTROL_3': {'any title 1': 'My control 3', 'any title_2, including support for commas': ''},
        'MY_CONTROL_4': {'any title 1': '', 'any title_2, including support for commas': 'Description 4'},
        'MY_CONTROL_5': {'any title 1': 'My control 5', 'any title_2, including support for commas': 'Description 5'}
    }, "Dictionary data does not match expected values"

# Sample CSV content with multiple lines and missing entries
valid_multiline_csv = "scf1;scf2,framework1;framework2\nscf4,framework8;framework2\nscf3,framework3"
missing_entries_csv = "scf1;scf2,\n,framework1;framework2\nscf3,framework3"

def test_validate_and_get_framework_success_multiline():
    # Mock reading from a CSV with valid, multiline data
    with patch("pandas.read_csv", return_value=pd.DataFrame([
        ["scf1;scf2", "framework1;framework2"],
        ["scf4;scf2", "framework8;framework2"],
        ["scf3", "framework3"]
    ], columns=[0, 1])):
        result = validate_and_get_framework("dummy_path.csv", "Framework")
        expected = pd.DataFrame([
            ["scf1", "framework1"],
            ["scf1", "framework2"],
            ["scf2", "framework1"],
            ["scf2", "framework2"],
            ["scf4", "framework8"],
            ["scf4", "framework2"],
            ["scf2", "framework8"],
            ["scf3", "framework3"]
        ], columns=['SCF', 'Framework'])
        # Resetting index to compare DataFrames accurately
        result = result.reset_index(drop=True)
        expected = expected.reset_index(drop=True)
        assert_frame_equal(result, expected)

def test_validate_and_get_framework_missing_entries():
    # Mock reading from a CSV where one side of the semicolon is missing
    with patch("pandas.read_csv", return_value=pd.DataFrame([
        ["scf1;scf2", pd.NA],
        [float('nan'), "framework1;framework2"],
        [None, "framework4"],
        ["scf3", "framework3"]
    ], columns=[0, 1])):
        result = validate_and_get_framework("dummy_path.csv", "Framework")
        expected = pd.DataFrame([
            ["scf3", "framework3"]
        ], columns=['SCF', 'Framework'])
        assert_frame_equal(result, expected)

# Additional test cases from previous example
def test_validate_and_get_framework_failure_column_mismatch():
    # Mock reading from a CSV with invalid data
    with patch("pandas.read_csv", return_value=pd.DataFrame([
        ["only_one_column"]
    ], columns=[0])):
        with pytest.raises(ValueError) as exc_info:
            validate_and_get_framework("dummy_path.csv", "Framework")
        assert "should have exactly 2 columns" in str(exc_info.value)

def test_validate_and_get_framework_file_not_found():
    # Simulate file not found by throwing FileNotFoundError
    with patch("pandas.read_csv", side_effect=FileNotFoundError("File not found")):
        with pytest.raises(FileNotFoundError) as exc_info:
            validate_and_get_framework("nonexistent_path.csv", "Framework")
        assert "File not found" in str(exc_info.value)
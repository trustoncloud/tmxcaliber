import pytest
from tmxcaliber.cli import _get_version, is_file_or_dir, validate, map, scan_controls, get_input_data, get_drawio_binary_path, output_result
import json
import os
import pandas as pd
from argparse import Namespace

import csv
from tmxcaliber.lib.threatmodel_data import ThreatModelData
from tmxcaliber.cli import BinaryNotFound, ArgumentTypeError

import pytest
from unittest.mock import patch, mock_open

@pytest.fixture
def mock_json_file(mock_json):
    return json.dumps(mock_json)

@pytest.fixture
def mock_json():
    return {'controls': {'someservice.C1': {
      "feature_class": ["someservice.FC1"],
      "objective": 'someservice.CO1',
      "weighted_priority": "High"}}, 'control_objectives': {'someservice.CO1':{'scf':['SCF1']}}}

def test_get_version():
    version = _get_version()
    assert isinstance(version, str)
    assert version.startswith('tmxcaliber')

def test_is_file_or_dir():
    with pytest.raises(ArgumentTypeError, match="The path nonexistentpath.json does not exist"):
        is_file_or_dir("nonexistentpath.json")
    assert is_file_or_dir("existingfile.json") == "existingfile.json"
    assert is_file_or_dir("existingdir") == "existingdir"

def test_validate():
    args = Namespace(operation='filter', severity='high', events='login', permissions='read', feature_classes='someservice.FC123,someservice.FC456', ids='someservice.CO123,someservice.FC123')
    validated_args = validate(args)
    assert validated_args.filter_obj.severity == 'high'
    assert 'login' in validated_args.filter_obj.events
    assert 'read' in validated_args.filter_obj.permissions
    assert validated_args.filter_obj.feature_classes == ['SOMESERVICE.FC123','SOMESERVICE.FC456']
    assert validated_args.filter_obj.ids == ['SOMESERVICE.CO123', 'SOMESERVICE.FC123']

def test_map(mock_json):
    framework2co = pd.DataFrame({'SCF': ['SCF1'], 'Framework': ['Framework1']})
    threatmodel_data = ThreatModelData(mock_json)
    metadata = {'Framework1': {'additional_info': 'info'}}
    result = map(framework2co, threatmodel_data, 'Framework', metadata)
    expected_result = {
        'Framework1': {
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
        with pytest.raises(json.JSONDecodeError):
            get_input_data(args)

def test_get_input_data_nonexistent_file():
    args = Namespace(source='nonexistent.json', operation='list')
    with patch('os.path.isfile', return_value=False), \
         patch('os.path.isdir', return_value=False):
        with pytest.raises(FileNotFoundError):
            get_input_data(args)

def test_get_drawio_binary_path():
    path = get_drawio_binary_path()
    assert os.path.exists(path)

def test_output_result():
    output_param = 'output.json'
    result = {'key': 'value'}
    output_result(output_param, result, 'json')
    with open(output_param, 'r') as file:
        data = json.load(file)
    assert data['key'] == 'value'

def test_is_file_or_dir():
    with pytest.raises(ArgumentTypeError, match="The path nonexistentpath.json does not exist"):
        is_file_or_dir("nonexistentpath.json")
def test_is_file_or_dir_invalid_file_type():
    with pytest.raises(SystemExit):
        is_file_or_dir("invalidfiletype.txt")

def test_validate_missing_required_fields():
    args = Namespace(operation='filter', severity='high')
    with pytest.raises(SystemExit):
        validate(args)

def test_map_empty_data():
    framework2co = pd.DataFrame()
    threatmodel_data = {'controls': {}, 'control_objectives': {}}
    metadata = {}
    result = map(framework2co, threatmodel_data, 'Framework1', metadata)
    assert result == {}

def test_scan_controls_no_match():
    args = Namespace(pattern='NonexistentPattern')
    data = {'controls': {'1': {'description': 'Authorized access granted'}}}
    result = scan_controls(args, data)
    assert result['controls'] == {}

def test_get_input_data_multiple_files():
    args = Namespace(source='validpath', operation='list')
    with pytest.raises(SystemExit):
        get_input_data(args)

def test_get_drawio_binary_path_not_found():
    with pytest.raises(BinaryNotFound):
        get_drawio_binary_path()

def test_output_result_csv():
    output_param = 'output.csv'
    result = [['header1', 'header2'], ['data1', 'data2']]
    output_result(output_param, result, 'csv_list')
    with open(output_param, 'r') as file:
        data = csv.reader(file)
        assert list(data) == [['header1', 'header2'], ['data1', 'data2']]

def test_output_result_unsupported_type():
    with pytest.raises(TypeError):
        output_result(None, None, 'unsupported_type')

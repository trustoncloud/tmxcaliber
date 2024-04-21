import pytest
from tmxcaliber.cli import _get_version, is_file_or_dir, validate, map, scan_controls, get_input_data, get_drawio_binary_path, output_result
import json
import os
import pandas as pd
from argparse import Namespace

def test_get_version():
    version = _get_version()
    assert isinstance(version, str)
    assert version.startswith('tmxcaliber ')

def test_is_file_or_dir():
    with pytest.raises(SystemExit):
        is_file_or_dir("nonexistentpath.json")
    assert is_file_or_dir("existingfile.json") == "existingfile.json"
    assert is_file_or_dir("existingdir") == "existingdir"

def test_validate():
    args = Namespace(operation='filter', severity='high', events='login', permissions='read', feature_classes='User', ids='123')
    validated_args = validate(args)
    assert validated_args.filter_obj.severity == 'high'
    assert 'login' in validated_args.filter_obj.events
    assert 'read' in validated_args.filter_obj.permissions
    assert 'User' in validated_args.filter_obj.feature_classes
    assert '123' in validated_args.filter_obj.ids

def test_map():
    framework2co = pd.DataFrame({'SCF': ['SCF1'], 'Framework': ['Framework1']})
    threatmodel_data = {'controls': {}, 'control_objectives': {}}
    metadata = {'Framework1': {'additional_info': 'info'}}
    result = map(framework2co, threatmodel_data, 'Framework1', metadata)
    assert 'Framework1' in result
    assert result['Framework1']['additional_info'] == 'info'

def test_scan_controls():
    args = Namespace(pattern='UnauthorizedAccess')
    data = {'controls': {'1': {'description': 'Unauthorized access detected'}}}
    result = scan_controls(args, data)
    assert '1' in result['controls']

def test_get_input_data():
    args = Namespace(source='validpath.json', operation='list')
    result = get_input_data(args)
    assert isinstance(result, list)  # Assuming JSON loads to a list

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
    with pytest.raises(SystemExit):
        is_file_or_dir("nonexistentpath.json")

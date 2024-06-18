import pytest
from tmxcaliber.parsers import is_file, is_file_or_dir, ArgumentTypeError

@pytest.fixture
def mock_filesystem(tmp_path):
    # Create mock paths
    valid_json_file = tmp_path / "valid_file.json"
    valid_json_file.touch()

    valid_xml_file = tmp_path / "valid_file.xml"
    valid_xml_file.touch()

    invalid_file = tmp_path / "invalid_file.txt"
    invalid_file.touch()

    valid_directory = tmp_path / "valid_directory"
    valid_directory.mkdir()

    return {
        "valid_json_file": str(valid_json_file),
        "valid_xml_file": str(valid_xml_file),
        "invalid_file": str(invalid_file),
        "valid_directory": str(valid_directory),
        "non_existent_path": str(tmp_path / "non_existent"),
    }

def test_valid_json_file(mock_filesystem):
    path = mock_filesystem["valid_json_file"]
    assert is_file_or_dir(path) == path

def test_valid_xml_file(mock_filesystem):
    path = mock_filesystem["valid_xml_file"]
    assert is_file_or_dir(path) == path

def test_invalid_file(mock_filesystem):
    path = mock_filesystem["invalid_file"]
    with pytest.raises(ArgumentTypeError, match="The file .* is not valid, only json or xml can be given."):
        is_file_or_dir(path)

def test_valid_directory(mock_filesystem):
    path = mock_filesystem["valid_directory"]
    assert is_file_or_dir(path) == path

def test_non_existent_path(mock_filesystem):
    path = mock_filesystem["non_existent_path"]
    with pytest.raises(ArgumentTypeError, match="The path .* does not exist."):
        is_file_or_dir(path)

@pytest.fixture
def mock_filesystem_paths(tmp_path):
    # Create mock paths
    valid_json_file = tmp_path / "valid_file.json"
    valid_json_file.touch()

    valid_xml_file = tmp_path / "valid_file.xml"
    valid_xml_file.touch()

    invalid_file = tmp_path / "invalid_file.txt"
    invalid_file.touch()

    non_file = tmp_path / "non_file"
    non_file.mkdir()

    return {
        "valid_json_file": str(valid_json_file),
        "valid_xml_file": str(valid_xml_file),
        "invalid_file": str(invalid_file),
        "non_file": str(non_file),
        "non_existent_path": str(tmp_path / "non_existent"),
    }

def test_is_file_with_valid_json_file(mock_filesystem_paths):
    path = mock_filesystem_paths["valid_json_file"]
    assert is_file(path) == path

def test_is_file_with_valid_xml_file(mock_filesystem_paths):
    path = mock_filesystem_paths["valid_xml_file"]
    assert is_file(path) == path

def test_is_file_with_invalid_file(mock_filesystem_paths):
    path = mock_filesystem_paths["invalid_file"]
    with pytest.raises(ArgumentTypeError, match="The file .* is not valid, only json or XML can be given."):
        is_file(path)

def test_is_file_with_non_file(mock_filesystem_paths):
    path = mock_filesystem_paths["non_file"]
    with pytest.raises(ArgumentTypeError, match="The path .* is not a file."):
        is_file(path)

def test_is_file_with_non_existent_path(mock_filesystem_paths):
    path = mock_filesystem_paths["non_existent_path"]
    with pytest.raises(ArgumentTypeError, match="The path .* does not exist."):
        is_file(path)

import pytest

from tmxcaliber import parsers as parsers_module
from tmxcaliber.parsers import (
    ArgumentTypeError,
    is_file,
    is_file_or_dir,
    valid_csv_path,
)


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
    with pytest.raises(
        ArgumentTypeError,
        match=r"The file .* is not valid, only json or xml can be given\.",
    ):
        is_file_or_dir(path)


def test_valid_directory(mock_filesystem):
    path = mock_filesystem["valid_directory"]
    assert is_file_or_dir(path) == path


def test_non_existent_path(mock_filesystem):
    path = mock_filesystem["non_existent_path"]
    with pytest.raises(ArgumentTypeError, match=r"The path .* does not exist\."):
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
    with pytest.raises(
        ArgumentTypeError,
        match=r"The file .* is not valid, only json or XML can be given\.",
    ):
        is_file(path)


def test_is_file_with_non_file(mock_filesystem_paths):
    path = mock_filesystem_paths["non_file"]
    with pytest.raises(ArgumentTypeError, match=r"The path .* is not a file\."):
        is_file(path)


def test_is_file_with_non_existent_path(mock_filesystem_paths):
    path = mock_filesystem_paths["non_existent_path"]
    with pytest.raises(ArgumentTypeError, match=r"The path .* does not exist\."):
        is_file(path)


def test_is_file_or_dir_rejects_paths_that_are_neither_files_nor_directories(
    monkeypatch,
):
    monkeypatch.setattr(parsers_module.os.path, "exists", lambda path: True)
    monkeypatch.setattr(parsers_module.os.path, "isfile", lambda path: False)
    monkeypatch.setattr(parsers_module.os.path, "isdir", lambda path: False)

    with pytest.raises(
        ArgumentTypeError,
        match=r"The path mystery-path is neither a file nor a directory\.",
    ):
        is_file_or_dir("mystery-path")


def test_valid_csv_path_accepts_consistent_csv(tmp_path):
    source = tmp_path / "valid.csv"
    source.write_text("id,name\n1,alpha\n2,beta\n", encoding="utf-8")

    assert valid_csv_path(str(source)) == str(source)


def test_valid_csv_path_rejects_empty_files(tmp_path):
    source = tmp_path / "empty.csv"
    source.write_text("", encoding="utf-8")

    with pytest.raises(ArgumentTypeError, match="CSV file is empty"):
        valid_csv_path(str(source))


def test_valid_csv_path_rejects_inconsistent_row_lengths(tmp_path):
    source = tmp_path / "invalid.csv"
    source.write_text("id,name\n1,alpha,extra\n", encoding="utf-8")

    with pytest.raises(
        ArgumentTypeError, match="does not match first row column count"
    ):
        valid_csv_path(str(source))


@pytest.mark.parametrize("command", [["filter"], ["list", "threats"]])
def test_permissions_help_shows_the_wildcard_in_double_quotes(command, capsys):
    # Double quotes are the one form PowerShell, cmd, bash and zsh all pass
    # through unchanged; cmd keeps single quotes as part of the value.
    parser = parsers_module.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation")
    parsers_module.add_filter_parser(subparsers)
    parsers_module.add_list_parser(subparsers)

    with pytest.raises(SystemExit):
        parser.parse_args([*command, "-h"])
    rendered = " ".join(capsys.readouterr().out.split())

    assert '--permissions "s3:Get*"' in rendered

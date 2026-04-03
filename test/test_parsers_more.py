import pytest

from tmxcaliber import parsers as parsers_module
from tmxcaliber.parsers import ArgumentTypeError, is_file_or_dir, valid_csv_path


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


def test_is_file_or_dir_rejects_paths_that_are_neither_files_nor_directories(
    monkeypatch,
):
    monkeypatch.setattr(parsers_module.os.path, "exists", lambda path: True)
    monkeypatch.setattr(parsers_module.os.path, "isfile", lambda path: False)
    monkeypatch.setattr(parsers_module.os.path, "isdir", lambda path: False)

    with pytest.raises(
        ArgumentTypeError,
        match="The path mystery-path is neither a file nor a directory.",
    ):
        is_file_or_dir("mystery-path")

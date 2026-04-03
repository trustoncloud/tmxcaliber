import pytest
from openpyxl import Workbook

from tmxcaliber.lib import scf as scf_module
from tmxcaliber.lib.errors import FrameworkNotFoundError


def test_supported_scf_versions_and_latest_are_consistent():
    supported = list(scf_module.get_supported_scf())

    assert supported
    assert scf_module.get_latest_supported_scf() == sorted(supported)[-1]


def test_get_scf_config_rejects_unknown_versions():
    with pytest.raises(ValueError, match="Unsupported SCF version requested"):
        scf_module.get_scf_config("1999.1")


def write_scf_workbook(path, rows, *, sheet_name):
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = sheet_name
    for row in rows:
        worksheet.append(row)
    workbook.save(path)
    workbook.close()


def test_get_full_scf_data_reads_cached_excel(monkeypatch, tmp_path):
    workbook_path = tmp_path / "cached.xlsx"
    write_scf_workbook(
        workbook_path,
        [
            ["SCF #", "Framework\nName", "Notes"],
            ["SCF1", "Control A\nControl B", " Alpha "],
            ["SCF2", "Control C", None],
        ],
        sheet_name=scf_module.scf_versions["2025.3.1"]["sheet_name"],
    )

    monkeypatch.setattr(
        scf_module, "get_cached_local_path_for", lambda url: str(workbook_path)
    )

    result = scf_module.get_full_scf_data("2025.3.1")

    assert result == [
        {
            "SCF #": "SCF1",
            "Framework\nName": "Control A\nControl B",
            "Notes": " Alpha ",
        },
        {"SCF #": "SCF2", "Framework\nName": "Control C", "Notes": None},
    ]


def test_get_valid_scf_controls_returns_the_scf_column(monkeypatch):
    monkeypatch.setattr(
        scf_module,
        "get_full_scf_data",
        lambda version: [{"SCF #": "SCF1"}, {"SCF #": "SCF2"}, {"SCF #": "   "}],
    )

    assert scf_module.get_valid_scf_controls("2025.3.1") == ["SCF1", "SCF2"]


def test_get_scf_data_normalizes_columns_and_explodes_newline_separated_values(
    monkeypatch,
):
    monkeypatch.setattr(
        scf_module,
        "get_full_scf_data",
        lambda version: [
            {"SCF #": "SCF1", "Framework\nName": "Control A\nControl B"},
            {"SCF #": "SCF2", "Framework\nName": "  Control C  "},
            {"SCF #": "SCF3", "Framework\nName": ""},
            {"SCF #": "SCF4", "Framework\nName": None},
        ],
    )

    result = scf_module.get_scf_data("2025.3.1", "Framework Name")
    expected = [
        ("SCF1", "Control A"),
        ("SCF1", "Control B"),
        ("SCF2", "Control C"),
    ]

    assert result == expected


def test_get_scf_data_raises_a_framework_not_found_error(monkeypatch):
    monkeypatch.setattr(
        scf_module,
        "get_full_scf_data",
        lambda version: [{"SCF #": "SCF1", "Other Framework": "Ctrl"}],
    )

    with pytest.raises(FrameworkNotFoundError, match="Missing Framework"):
        scf_module.get_scf_data("2025.3.1", "Missing Framework")

import argparse
import json
import sys
from argparse import Namespace
from importlib import metadata
from unittest.mock import mock_open, patch

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber.cli import (
    _get_version,
    get_feature_class_rows,
    get_file_paths,
    get_input_data,
    get_metadata,
    get_recursive_json_file_paths,
    get_service_rows,
    load_json_data,
    output_result,
    repair_json_strings,
    scan_controls,
)
from tmxcaliber.lib.errors import FeatureClassCycleError
from tmxcaliber.lib.threatmodel_data import ThreatModelData
from tmxcaliber.params import GUARDDUTY_PATTERN_NAME


@pytest.fixture(autouse=True)
def reset_threatmodel_data_list():
    ThreatModelData.threatmodel_data_list = []
    yield
    ThreatModelData.threatmodel_data_list = []


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def make_threatmodel(
    *,
    release="1710000000",
    provider="aws",
    service="s3",
    controls=None,
    control_objectives=None,
    threats=None,
    feature_classes=None,
    actions=None,
    scorecard=None,
    dfd_body=None,
):
    metadata_block = {"release": release, "name": "TM"}
    if provider is not None:
        metadata_block["provider"] = provider
    if service is not None:
        metadata_block["service"] = service

    threatmodel = {
        "metadata": metadata_block,
        "controls": controls or {},
        "control_objectives": control_objectives or {},
        "threats": threats or {},
        "feature_classes": feature_classes or {},
        "actions": actions or {},
    }
    if scorecard is not None:
        threatmodel["scorecard"] = scorecard
    if dfd_body is not None:
        threatmodel["dfd"] = {"body": dfd_body}
    return threatmodel


def test_get_version_when_package_metadata_is_missing(monkeypatch):
    monkeypatch.setattr(
        cli_module.metadata,
        "version",
        lambda _: (_ for _ in ()).throw(metadata.PackageNotFoundError()),
    )

    assert _get_version() == "tmxcaliber version not found"


def test_repair_json_strings_fixes_unescaped_href_quote():
    repaired = repair_json_strings(
        '{"html":"<a href=\\"https://example.com">Example</a>"}'
    )

    assert repaired == {"html": '<a href="https://example.com">Example</a>'}


def test_load_json_data_repairs_invalid_json(tmp_path, capsys):
    source = tmp_path / "broken.json"
    source.write_text(
        '{"html":"<a href=\\"https://example.com">Example</a>"}',
        encoding="utf-8",
    )

    assert load_json_data(str(source)) == {
        "html": '<a href="https://example.com">Example</a>'
    }
    captured = capsys.readouterr().out
    assert "Trying to repair" in captured
    assert "Repair successful!" in captured


def test_load_json_data_exits_when_repair_fails(tmp_path, monkeypatch, capsys):
    source = tmp_path / "broken.json"
    source.write_text("{not-json", encoding="utf-8")

    def raise_decode_error(_value):
        raise json.JSONDecodeError("bad json", "{not-json", 1)

    monkeypatch.setattr(cli_module, "repair_json_strings", raise_decode_error)

    with pytest.raises(SystemExit):
        load_json_data(str(source))

    assert "Repair failed. Exiting." in capsys.readouterr().out


def test_load_json_data_exits_when_file_is_missing(capsys):
    with pytest.raises(SystemExit):
        load_json_data("missing.json")

    assert "File not found: missing.json" in capsys.readouterr().out


def test_get_file_paths_filters_to_json_files(tmp_path):
    valid = tmp_path / "a.json"
    invalid = tmp_path / "b.txt"
    valid.write_text("{}", encoding="utf-8")
    invalid.write_text("ignored", encoding="utf-8")

    assert get_file_paths(str(valid)) == [str(valid)]
    assert get_file_paths(str(invalid)) == []
    assert get_file_paths(str(tmp_path)) == [str(valid)]


def test_get_file_paths_sorts_directory_json_files(tmp_path):
    later = tmp_path / "b.json"
    earlier = tmp_path / "a.json"
    later.write_text("{}", encoding="utf-8")
    earlier.write_text("{}", encoding="utf-8")

    assert get_file_paths(str(tmp_path)) == [str(earlier), str(later)]


def test_get_recursive_json_file_paths_rejects_non_json_file(tmp_path):
    source = tmp_path / "service.xml"
    source.write_text("<xml />", encoding="utf-8")

    with pytest.raises(SystemExit):
        get_recursive_json_file_paths(str(source))


def test_get_input_data_reads_xml_source_for_generate(tmp_path):
    source = tmp_path / "aws_s3_DFD.xml"
    source.write_text("<mxfile />", encoding="utf-8")

    args = Namespace(source=str(source), operation="generate")

    assert get_input_data(args) == "<mxfile />"


def test_get_input_data_rejects_multiple_json_files_for_non_list_operation(tmp_path):
    write_json(tmp_path / "first.json", {})
    write_json(tmp_path / "second.json", {})

    args = Namespace(source=str(tmp_path), operation="filter")

    with pytest.raises(argparse.ArgumentTypeError, match="Only 1 file can be given"):
        get_input_data(args)


def test_get_input_data_rejects_invalid_non_json_or_xml_source(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text("hello", encoding="utf-8")

    with pytest.raises(SystemExit):
        get_input_data(Namespace(source=str(source), operation="generate"))

    assert f"Invalid file type for {source}" in capsys.readouterr().out


def test_output_result_writes_removed_json_when_output_has_no_extension():
    mocked_open = mock_open()

    with patch("builtins.open", mocked_open):
        output_result(
            "result", {"kept": True}, "json", output_removed_json={"gone": True}
        )

    assert mocked_open.call_args_list[0].args[0] == "result"
    assert mocked_open.call_args_list[1].args[0] == "result_removed"


def test_output_result_supports_markdown_file_and_stdout(tmp_path, capsys):
    output = tmp_path / "result.md"
    markdown = "## Heading"

    output_result(str(output), markdown, "md")
    output_result(None, markdown, "md")

    assert output.read_text(encoding="utf-8") == markdown
    assert capsys.readouterr().out.strip() == markdown


def test_get_metadata_duplicate_rows_keep_first_values(tmp_path):
    metadata_csv = tmp_path / "metadata.csv"
    metadata_csv.write_text(
        "id,owner,priority\n" "Control1,Team A,High\n" "Control1,Team B,Low\n",
        encoding="utf-8",
    )

    fields, rows = get_metadata(str(metadata_csv))

    assert fields == ["owner", "priority"]
    assert rows == {"Control1": {"owner": "Team A", "priority": "High"}}


def test_scan_controls_supports_guardduty_pattern_alias():
    args = Namespace(pattern=GUARDDUTY_PATTERN_NAME)
    data = {
        "controls": {
            "Svc.C1": {"description": "Discovery:IAMUser/AnomalousBehavior"},
            "Svc.C2": {"description": "No match here"},
        }
    }

    result = scan_controls(args, data)

    assert result == {
        "controls": {"Svc.C1": {"description": "Discovery:IAMUser/AnomalousBehavior"}}
    }


def test_get_service_rows_skips_non_dict_metadata(tmp_path):
    source = write_json(tmp_path / "service.json", {"metadata": ["not-a-dict"]})

    assert get_service_rows(str(source)) == []


def test_get_feature_class_rows_returns_empty_when_feature_classes_is_not_a_dict(
    tmp_path,
):
    source = write_json(tmp_path / "service.json", {"feature_classes": []})

    assert get_feature_class_rows(str(source)) == []


def test_main_list_threats_applies_severity_filter(tmp_path, monkeypatch, capsys):
    source = write_json(
        tmp_path / "tm.json",
        make_threatmodel(
            threats={
                "Svc.T10": {
                    "name": "High threat",
                    "feature_class": "Svc.FC1",
                    "cvss_severity": "High",
                    "access": {"AND": ["perm.read"]},
                },
                "Svc.T2": {
                    "name": "Low threat",
                    "feature_class": "Svc.FC1",
                    "cvss_severity": "Low",
                    "access": {"AND": ["perm.write"]},
                },
            },
            feature_classes={"Svc.FC1": {"class_relationship": []}},
            controls={},
            control_objectives={},
        ),
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "threats", "--severity", "high", str(source)],
    )

    cli_module.main()
    output = capsys.readouterr().out.strip().splitlines()

    assert output[0] == "id,name,feature_class,cvss_severity,access"
    assert output[1:] == [
        'Svc.T10,High threat,Svc.FC1,High,"{""AND"": [""perm.read""]}"'
    ]


def test_main_list_threats_with_ids_uses_later_matching_model_in_directory(
    tmp_path, monkeypatch, capsys
):
    write_json(
        tmp_path / "a.json",
        make_threatmodel(
            threats={
                "Svc.T1": {
                    "name": "Unrelated threat",
                    "feature_class": "Svc.FC1",
                    "access": {"AND": ["perm.read"]},
                }
            }
        ),
    )
    write_json(
        tmp_path / "b.json",
        make_threatmodel(
            threats={
                "Vpc.T73": {
                    "name": "Threat 73",
                    "feature_class": "Vpc.FC1",
                    "access": {"AND": ["ec2:DescribeVpcs"]},
                },
                "Vpc.T74": {
                    "name": "Threat 74",
                    "feature_class": "Vpc.FC1",
                    "access": {"AND": ["ec2:ModifyVpcBlockPublicAccessOptions"]},
                },
            }
        ),
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "list", "threats", str(tmp_path), "--ids", "Vpc.T73,Vpc.T74"],
    )

    cli_module.main()
    output = capsys.readouterr().out.strip().splitlines()

    assert output == [
        "id,name,feature_class,access",
        'Vpc.T73,Threat 73,Vpc.FC1,"{""AND"": [""ec2:DescribeVpcs""]}"',
        'Vpc.T74,Threat 74,Vpc.FC1,"{""AND"": [""ec2:ModifyVpcBlockPublicAccessOptions""]}"',
    ]


def test_main_scan_outputs_json(tmp_path, monkeypatch, capsys):
    source = write_json(
        tmp_path / "tm.json",
        make_threatmodel(
            controls={
                "Svc.C1": {"description": "Discovery:IAMUser/AnomalousBehavior"},
                "Svc.C2": {"description": "no findings here"},
            }
        ),
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "scan", "--pattern", GUARDDUTY_PATTERN_NAME, str(source)],
    )

    cli_module.main()
    result = json.loads(capsys.readouterr().out)

    assert list(result["controls"].keys()) == ["Svc.C1"]


def test_get_params_rejects_xml_files_that_are_not_main_dfd(tmp_path, monkeypatch):
    source = tmp_path / "service.xml"
    source.write_text("<mxfile />", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["prog", "generate", str(source)])

    with pytest.raises(SystemExit):
        cli_module.get_params()


def test_main_wraps_feature_class_cycle_errors_as_system_exit(monkeypatch):
    monkeypatch.setattr(cli_module, "get_params", lambda: Namespace(operation="filter"))
    monkeypatch.setattr(
        cli_module,
        "get_input_data",
        lambda _params: (_ for _ in ()).throw(FeatureClassCycleError(["Svc.FC1"])),
    )

    with pytest.raises(SystemExit, match="Invalid Feature Class relationships"):
        cli_module.main()

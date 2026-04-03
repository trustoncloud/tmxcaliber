import json
import sys
from base64 import b64encode

import pytest

from tmxcaliber import cli as cli_module
from tmxcaliber.lib.errors import BinaryNotFound
from tmxcaliber.lib.threatmodel_data import ThreatModelData
from tmxcaliber.params import METADATA_MISSING


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


def test_main_map_csv_outputs_metadata_defaults(tmp_path, monkeypatch, capsys):
    source = write_json(
        tmp_path / "tm.json",
        make_threatmodel(
            controls={
                "Svc.C10": {
                    "objective": "Svc.CO1",
                    "weighted_priority": "High",
                    "description": "Control 10",
                },
                "Svc.C2": {
                    "objective": "Svc.CO2",
                    "weighted_priority": "Low",
                    "description": "Control 2",
                },
            },
            control_objectives={
                "Svc.CO1": {"description": "Objective 1", "scf": ["SCF1"]},
                "Svc.CO2": {"description": "Objective 2", "scf": ["SCF2"]},
            },
        ),
    )
    framework_map = tmp_path / "framework_map.csv"
    framework_map.write_text("SCF1,Framework10\nSCF2,Framework2\n", encoding="utf-8")
    metadata_csv = tmp_path / "framework_metadata.csv"
    metadata_csv.write_text("id,owner\nFramework2,Team 2\n", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "map",
            "--scf",
            "2025.3.1",
            "--framework-name",
            "Framework",
            "--framework-map",
            str(framework_map),
            "--framework-metadata",
            str(metadata_csv),
            "--format",
            "csv",
            str(source),
        ],
    )

    cli_module.main()
    output = capsys.readouterr().out.strip().splitlines()

    assert output[0] == (
        "Framework,SCF,Control Objectives,Control - Very High,Control - High,"
        "Control - Medium,Control - Low,Control - Very Low,owner"
    )
    assert "Framework2,SCF2,Svc.CO2,,,,Svc.C2,,Team 2" in output[1:]
    assert f"Framework10,SCF1,Svc.CO1,,Svc.C10,,,,{METADATA_MISSING}" in output[1:]


def test_main_add_mapping_writes_mapping_and_backfills_control_objectives(
    tmp_path, monkeypatch
):
    source = write_json(
        tmp_path / "tm.json",
        make_threatmodel(
            controls={
                "Svc.C10": {
                    "objective": "Svc.CO1",
                    "weighted_priority": "High",
                    "description": "Control 10",
                },
                "Svc.C2": {
                    "objective": "Svc.CO2",
                    "weighted_priority": "Low",
                    "description": "Control 2",
                },
            },
            control_objectives={
                "Svc.CO1": {"description": "Objective 1", "scf": ["SCF1"]},
                "Svc.CO2": {"description": "Objective 2", "scf": ["SCF2"]},
            },
        ),
    )
    framework_map = tmp_path / "framework_map.csv"
    framework_map.write_text("SCF1,Framework10\nSCF2,Framework2\n", encoding="utf-8")
    metadata_csv = tmp_path / "metadata.csv"
    metadata_csv.write_text("id,owner\nFramework2,Team 2\n", encoding="utf-8")
    output = tmp_path / "mapped.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "add-mapping",
            "--scf",
            "2025.3.1",
            "--framework-name",
            "Framework",
            "--framework-map",
            str(framework_map),
            "--framework-metadata",
            str(metadata_csv),
            "--output",
            str(output),
            str(source),
        ],
    )

    cli_module.main()
    result = json.loads(output.read_text(encoding="utf-8"))

    assert list(result["mapping"].keys()) == ["Framework10", "Framework2"]
    assert result["mapping"]["Framework2"] == {
        "control_objectives": ["Svc.CO2"],
        "owner": "Team 2",
        "scf": ["SCF2"],
    }
    assert result["mapping"]["Framework10"] == {
        "control_objectives": ["Svc.CO1"],
        "owner": METADATA_MISSING,
        "scf": ["SCF1"],
    }
    assert result["control_objectives"]["Svc.CO1"]["Framework"] == ["Framework10"]
    assert result["control_objectives"]["Svc.CO2"]["Framework"] == ["Framework2"]


@pytest.mark.parametrize(
    ("fmt", "expected_fragment"),
    [("json", '"change_type": "modified"'), ("md", "## Changes Summary")],
)
def test_main_create_change_log_outputs_requested_format(
    tmp_path, monkeypatch, fmt, expected_fragment
):
    old_source = write_json(
        tmp_path / "old.json",
        make_threatmodel(
            release="1710000000",
            controls={
                "Svc.C1": {
                    "objective": "Svc.CO1",
                    "description": "Old control",
                    "weighted_priority": "High",
                    "mitigate": [{"threat": "Svc.T1"}],
                }
            },
            control_objectives={
                "Svc.CO1": {"description": "Objective 1", "scf": ["SCF1"]}
            },
            threats={
                "Svc.T1": {
                    "name": "Threat 1",
                    "feature_class": "Svc.FC1",
                    "cvss_severity": "High",
                    "access": {"AND": ["perm.read"]},
                }
            },
            feature_classes={"Svc.FC1": {"name": "FC1", "class_relationship": []}},
        ),
    )
    new_source = write_json(
        tmp_path / "new.json",
        make_threatmodel(
            release="1710000100",
            controls={
                "Svc.C1": {
                    "objective": "Svc.CO1",
                    "description": "New control",
                    "weighted_priority": "High",
                    "mitigate": [{"threat": "Svc.T1"}],
                }
            },
            control_objectives={
                "Svc.CO1": {"description": "Objective 1", "scf": ["SCF1"]}
            },
            threats={
                "Svc.T1": {
                    "name": "Threat 1",
                    "feature_class": "Svc.FC1",
                    "cvss_severity": "High",
                    "access": {"AND": ["perm.read"]},
                }
            },
            feature_classes={"Svc.FC1": {"name": "FC1", "class_relationship": []}},
        ),
    )
    output = tmp_path / f"change-log.{fmt}"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "create-change-log",
            "--format",
            fmt,
            "--output",
            str(output),
            str(new_source),
            str(old_source),
        ],
    )

    cli_module.main()

    assert expected_fragment in output.read_text(encoding="utf-8")


def test_main_generate_from_xml_cleans_existing_dirs_and_calls_generators(
    tmp_path, monkeypatch
):
    source = tmp_path / "aws_s3_DFD.xml"
    source.write_text("<mxfile><diagram /></mxfile>", encoding="utf-8")
    threat_dir = tmp_path / "threats"
    fc_dir = tmp_path / "feature-classes"
    out_dir = tmp_path / "images"
    cleanup_xml_dir = tmp_path / "xml-cleanup"
    cleanup_img_dir = tmp_path / "img-cleanup"
    cleanup_xml_dir.mkdir()
    cleanup_img_dir.mkdir()

    calls = []
    monkeypatch.setattr(cli_module, "XML_DIR", str(cleanup_xml_dir))
    monkeypatch.setattr(cli_module, "IMG_DIR", str(cleanup_img_dir))
    monkeypatch.setattr(
        cli_module, "rmtree", lambda path: calls.append(("rmtree", path))
    )
    monkeypatch.setattr(
        cli_module,
        "generate_xml",
        lambda data, prefix, threat_dir_arg, fc_dir_arg, validate: calls.append(
            ("generate_xml", data, prefix, threat_dir_arg, fc_dir_arg, validate)
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "generate_pngs",
        lambda binary, input_dir, output_dir_arg, width: calls.append(
            ("generate_pngs", binary, input_dir, output_dir_arg, width)
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "generate",
            "--bin",
            "drawio",
            "--threat-dir",
            str(threat_dir),
            "--fc-dir",
            str(fc_dir),
            "--out-dir",
            str(out_dir),
            str(source),
        ],
    )

    cli_module.main()

    assert ("rmtree", str(cleanup_xml_dir)) in calls
    assert ("rmtree", str(cleanup_img_dir)) in calls
    assert (
        "generate_xml",
        "<mxfile><diagram /></mxfile>",
        "AWS_S3",
        str(threat_dir),
        str(fc_dir),
        False,
    ) in calls
    assert (
        "generate_pngs",
        "drawio",
        str(fc_dir),
        str(out_dir),
        1500,
    ) in calls
    assert (
        "generate_pngs",
        "drawio",
        str(threat_dir),
        str(out_dir),
        1500,
    ) in calls


def test_main_generate_from_json_uses_base64_body_and_single_png_run(
    tmp_path, monkeypatch
):
    xml_body = "<mxfile><diagram>body</diagram></mxfile>"
    source = write_json(
        tmp_path / "tm.json",
        make_threatmodel(
            dfd_body=b64encode(xml_body.encode("utf-8")).decode("ascii"),
        ),
    )
    shared_dir = tmp_path / "shared"
    out_dir = tmp_path / "images"

    calls = []
    monkeypatch.setattr(
        cli_module,
        "generate_xml",
        lambda data, prefix, threat_dir_arg, fc_dir_arg, validate: calls.append(
            ("generate_xml", data, prefix, threat_dir_arg, fc_dir_arg, validate)
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "generate_pngs",
        lambda binary, input_dir, output_dir_arg, width: calls.append(
            ("generate_pngs", binary, input_dir, output_dir_arg, width)
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog",
            "generate",
            "--bin",
            "drawio",
            "--threat-dir",
            str(shared_dir),
            "--fc-dir",
            str(shared_dir),
            "--out-dir",
            str(out_dir),
            str(source),
        ],
    )

    cli_module.main()

    assert (
        "generate_xml",
        xml_body,
        "AWS_S3",
        str(shared_dir),
        str(shared_dir),
        False,
    ) in calls
    assert (
        calls.count(("generate_pngs", "drawio", str(shared_dir), str(out_dir), 1500))
        == 1
    )


def test_main_generate_exits_when_drawio_binary_cannot_be_found(
    tmp_path, monkeypatch, capsys
):
    source = write_json(tmp_path / "tm.json", make_threatmodel())

    def raise_binary_not_found():
        raise BinaryNotFound("drawio binary missing")

    monkeypatch.setattr(cli_module, "get_drawio_binary_path", raise_binary_not_found)
    monkeypatch.setattr(sys, "argv", ["prog", "generate", str(source)])

    with pytest.raises(SystemExit):
        cli_module.main()

    assert "drawio binary missing" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (
            make_threatmodel(provider=None, service="s3", dfd_body="ignored"),
            "No `provider` or `service` in the JSON data.",
        ),
        (
            make_threatmodel(dfd_body=None),
            "Could not get `dfd.body` from the JSON data.",
        ),
    ],
)
def test_main_generate_exits_for_missing_json_metadata_or_body(
    tmp_path, monkeypatch, capsys, payload, expected_message
):
    source = write_json(tmp_path / "tm.json", payload)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "generate", "--bin", "drawio", str(source)],
    )

    with pytest.raises(SystemExit):
        cli_module.main()

    assert expected_message in capsys.readouterr().out

"""Selecting CCR rules from a manifest, and writing them from an archive."""

from __future__ import annotations

import hashlib
import io
import pathlib
import zipfile
from typing import Any

import pytest

from tmxcaliber.lib.remote.ccr import (
    RuleFilter,
    extract,
    rule_row,
    select_rules,
    verify_archive,
)
from tmxcaliber.lib.remote.errors import ContractViolation


def rule(
    rule_id: str,
    modes: list[str],
    *,
    cloud: bool = True,
    terraform: bool = True,
    files: list[str] | None = None,
) -> dict[str, Any]:
    """Build one manifest rule, shaped as `build_cache_payload.py` writes it.

    Args:
        rule_id: The control id.
        modes: The modes it ships.
        cloud: Whether the cloud matcher is implemented.
        terraform: Whether the Terraform matcher is implemented.
        files: The rule's files; one per mode and matcher when omitted.

    Returns:
        The rule.
    """
    if files is None:
        files = ["metadata.json"]
        for mode in modes:
            if cloud:
                files += [
                    f"{mode}/cloud/check.rego",
                    f"{mode}/cloud/tests/check_test.rego",
                ]
            if terraform:
                files.append(f"{mode}/terraform/check.rego")
    return {
        "id": rule_id,
        "name": "check",
        "modes": modes,
        "files": files,
        "weighted_priority": "High",
        "matchers": {
            "cloud": {"implemented": cloud, "file": None, "targets": []},
            "terraform": {"implemented": terraform, "file": None, "targets": []},
        },
    }


MANIFEST: dict[str, Any] = {
    "release_key": "aws-s3",
    "release_id": "d07d6aee",
    "rules": [
        rule("S3.C20", ["allowlist", "universal"]),
        rule("S3.C21", ["denylist"], cloud=False),
        rule(
            "S3.C22",
            ["allowlist"],
            files=[
                "metadata.json",
                "allowlist/remediation.md",
                "allowlist/terraform/remediation.md",
                "allowlist/terraform/check.rego",
            ],
            cloud=False,
        ),
    ],
}


def ids(wanted: RuleFilter) -> list[str]:
    """Select from the fixture and name what was chosen.

    Args:
        wanted: The filter.

    Returns:
        The chosen rule ids, in manifest order.
    """
    return [str(s.rule["id"]) for s in select_rules(MANIFEST, wanted)]


def test_no_filter_selects_every_rule_and_every_file() -> None:
    chosen = select_rules(MANIFEST, RuleFilter())

    assert [s.rule["id"] for s in chosen] == ["S3.C20", "S3.C21", "S3.C22"]
    assert chosen[0].files == tuple(MANIFEST["rules"][0]["files"])


def test_a_control_matches_its_id_whatever_the_case() -> None:
    assert ids(RuleFilter(controls=("s3.c21",))) == ["S3.C21"]


def test_repeats_of_one_flag_are_or() -> None:
    assert ids(RuleFilter(controls=("S3.C20", "S3.C22"))) == ["S3.C20", "S3.C22"]


def test_a_mode_selects_rules_that_ship_it() -> None:
    assert ids(RuleFilter(modes=("denylist",))) == ["S3.C21"]


def test_a_matcher_selects_rules_where_it_is_implemented() -> None:
    assert ids(RuleFilter(matchers=("cloud",))) == ["S3.C20"]


def test_different_flags_are_and() -> None:
    assert ids(RuleFilter(modes=("allowlist",), matchers=("cloud",))) == ["S3.C20"]


def test_a_mode_keeps_only_that_mode_folder_and_the_root() -> None:
    [chosen] = select_rules(
        MANIFEST, RuleFilter(controls=("S3.C20",), modes=("universal",))
    )

    assert chosen.files == (
        "metadata.json",
        "universal/cloud/check.rego",
        "universal/cloud/tests/check_test.rego",
        "universal/terraform/check.rego",
    )


def test_a_matcher_keeps_its_folder_mode_level_files_and_the_root() -> None:
    [chosen] = select_rules(
        MANIFEST, RuleFilter(controls=("S3.C22",), matchers=("terraform",))
    )

    assert chosen.files == (
        "metadata.json",
        "allowlist/remediation.md",
        "allowlist/terraform/remediation.md",
        "allowlist/terraform/check.rego",
    )


def test_a_matcher_drops_the_other_matchers_files() -> None:
    [chosen] = select_rules(
        MANIFEST, RuleFilter(controls=("S3.C20",), matchers=("terraform",))
    )

    assert chosen.files == (
        "metadata.json",
        "allowlist/terraform/check.rego",
        "universal/terraform/check.rego",
    )


def test_a_file_glob_matches_across_folders() -> None:
    chosen = select_rules(MANIFEST, RuleFilter(files=("*/terraform/*.rego",)))

    assert [s.rule["id"] for s in chosen] == ["S3.C20", "S3.C21", "S3.C22"]
    assert chosen[0].files == (
        "allowlist/terraform/check.rego",
        "universal/terraform/check.rego",
    )


def test_a_rule_with_no_file_matching_the_glob_is_not_selected() -> None:
    assert ids(RuleFilter(files=("*_test.rego",))) == ["S3.C20"]


def test_a_row_carries_the_pack_the_release_and_the_selected_files() -> None:
    [chosen] = select_rules(
        MANIFEST, RuleFilter(controls=("S3.C21",), files=("*.json",))
    )

    assert rule_row("aws-s3", "d07d6aee", chosen) == {
        "releaseKey": "aws-s3",
        "releaseId": "d07d6aee",
        "ruleId": "S3.C21",
        "name": "check",
        "modes": ["denylist"],
        "matchers": MANIFEST["rules"][1]["matchers"],
        "weightedPriority": "High",
        "files": ["metadata.json"],
    }


def test_a_rule_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ContractViolation):
        select_rules({"rules": ["S3.C20"]}, RuleFilter())


def archive_of(entries: dict[str, bytes]) -> bytes:
    """Zip entries the way the bundle is built: one file per entry.

    Args:
        entries: Each entry name and its content.

    Returns:
        The zip.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def pack(entries: dict[str, bytes]) -> tuple[bytes, dict[str, Any]]:
    """Build an archive and the manifest that describes it.

    Args:
        entries: The archive's entries.

    Returns:
        The archive, and a manifest declaring every entry under its rule.
    """
    data = archive_of(entries)
    rules: dict[str, list[str]] = {}
    for name in entries:
        rule_id, _, file = name.partition("/")
        rules.setdefault(rule_id, []).append(file)
    manifest = {
        "release_id": "d07d6aee",
        "bundle": {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)},
        "rules": [
            rule(rule_id, ["allowlist"], files=files)
            for rule_id, files in rules.items()
        ],
    }
    return data, manifest


ENTRIES = {
    "S3.C20/metadata.json": b"{}",
    "S3.C20/allowlist/cloud/check.rego": b"package a",
    "S3.C21/metadata.json": b"{}",
}


def test_a_matching_archive_verifies() -> None:
    data, manifest = pack(ENTRIES)

    verify_archive(data, manifest, "aws-s3")


@pytest.mark.parametrize(
    "block",
    [
        {"sha256": "0" * 64},
        {"bytes": 1},
        None,
    ],
    ids=["digest", "size", "absent"],
)
def test_an_archive_unlike_its_manifest_is_refused(block: Any) -> None:
    data, manifest = pack(ENTRIES)
    if block is None:
        del manifest["bundle"]
    else:
        manifest["bundle"] = {**manifest["bundle"], **block}

    with pytest.raises(ContractViolation):
        verify_archive(data, manifest, "aws-s3")


def test_only_the_selected_files_are_written(tmp_path: pathlib.Path) -> None:
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter(controls=("S3.C20",), files=("*.rego",)))

    written = extract(data, manifest, "aws-s3", chosen, tmp_path)

    target = tmp_path / "aws-s3" / "S3.C20" / "allowlist" / "cloud" / "check.rego"
    assert written == [target]
    assert target.read_bytes() == b"package a"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["aws-s3"]


@pytest.mark.parametrize(
    "extra",
    ["../escape.rego", "/abs/escape.rego", "S3.C20\\evil.rego", "S3.C20//x.rego"],
)
def test_an_unsafe_entry_refuses_the_whole_pack(
    tmp_path: pathlib.Path, extra: str
) -> None:
    data, manifest = pack(ENTRIES)
    data = archive_of({**ENTRIES, extra: b"x"})
    manifest["bundle"] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation):
        extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_an_entry_the_manifest_does_not_declare_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    _, manifest = pack(ENTRIES)
    data = archive_of({**ENTRIES, "S3.C99/metadata.json": b"{}"})
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation):
        extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_a_declared_file_missing_from_the_archive_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    _, manifest = pack(ENTRIES)
    data = archive_of({k: v for k, v in ENTRIES.items() if not k.endswith(".rego")})
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation):
        extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert list(tmp_path.iterdir()) == []

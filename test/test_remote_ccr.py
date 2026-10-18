"""Selecting CCR rules from a manifest, and writing them from an archive."""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import stat
import struct
import sys
import zipfile
from collections.abc import Callable
from typing import Any

import pytest

from tmxcaliber.lib.remote.ccr import (
    RuleFilter,
    _is_safe,
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


def archive_of(
    entries: dict[str, bytes], compression: int = zipfile.ZIP_STORED
) -> bytes:
    """Zip entries the way the bundle is built: one file per entry.

    Args:
        entries: Each entry name and its content.
        compression: The zip compression method for every entry.

    Returns:
        The zip.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def manifest_for(data: bytes, rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe an archive with a manifest whose rules are given by hand.

    Args:
        data: The archive.
        rules: The manifest's rules, which `pack` would never produce when a
            test needs a manifest that repeats a file or a rule.

    Returns:
        The manifest, with a bundle block that matches the archive.
    """
    return {
        "release_id": "d07d6aee",
        "bundle": {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)},
        "rules": rules,
    }


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
    return data, manifest_for(
        data,
        [rule(rule_id, ["allowlist"], files=files) for rule_id, files in rules.items()],
    )


ENTRIES = {
    "S3.C20/metadata.json": b"{}",
    "S3.C20/allowlist/cloud/check.rego": b"package a",
    "S3.C21/metadata.json": b"{}",
}


def test_a_matching_archive_verifies() -> None:
    data, manifest = pack(ENTRIES)

    verify_archive(data, manifest, "aws-s3")


@pytest.mark.parametrize(
    ("block", "code"),
    [
        ({"sha256": "0" * 64}, "archive_mismatch"),
        ({"bytes": 1}, "archive_mismatch"),
        (None, "bad_manifest"),
    ],
    ids=["digest", "size", "absent"],
)
def test_an_archive_unlike_its_manifest_is_refused(block: Any, code: str) -> None:
    data, manifest = pack(ENTRIES)
    if block is None:
        del manifest["bundle"]
    else:
        manifest["bundle"] = {**manifest["bundle"], **block}

    with pytest.raises(ContractViolation) as caught:
        verify_archive(data, manifest, "aws-s3")

    assert caught.value.code == code


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
    ["../escape.rego", "/abs/escape.rego", "S3.C20//x.rego"],
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

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


def with_raw_name(data: bytes, name: str, raw: str) -> bytes:
    """Store an entry under a name that ``zipfile`` would not write itself.

    ``zipfile`` rewrites ``os.sep`` to ``/`` in a name it is handed, so on
    Windows `archive_of` cannot produce a backslash. Replacing the bytes of the
    name can, on every platform. The name is stored twice, in the entry's local
    header and in the central directory, and both must change. The two names
    have the same length, so no offset in the zip moves.

    Args:
        data: The zip.
        name: The entry's name as `archive_of` wrote it.
        raw: The name to store instead, as long as ``name``.

    Returns:
        The zip, with the entry under its new name.
    """
    assert len(raw) == len(name)
    assert data.count(name.encode()) == 2
    return data.replace(name.encode(), raw.encode())


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("S3.C20/allowlist/cloud/check.rego", "S3.C20\\allowlist\\cloud\\check.rego"),
        ("S3.C20/allowlist/cloud/check.rego", "S3.C20/allowlist\\cloud/check.rego"),
        ("S3.C20/sub/", "S3.C20\\sub\\"),
    ],
    ids=["every-separator", "one-separator", "folder-entry"],
)
def test_a_backslash_in_a_stored_name_refuses_the_pack_on_every_platform(
    tmp_path: pathlib.Path, name: str, raw: str
) -> None:
    # On Windows zipfile reads a backslash back as "/", so a guard that looks at
    # the decoded name sees a declared file and writes it, while on Linux the
    # same bytes are refused. The stored name is the one to judge.
    entries = {**ENTRIES, "S3.C20/sub/": b""} if name.endswith("/") else ENTRIES
    data = with_raw_name(archive_of(entries), name, raw)
    manifest = manifest_for(data, pack(ENTRIES)[1]["rules"])
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


def test_a_folder_entry_in_the_archive_is_not_a_file_to_write(
    tmp_path: pathlib.Path,
) -> None:
    _, manifest = pack(ENTRIES)
    data = archive_of({"S3.C20/": b"", "S3.C20/allowlist/": b"", **ENTRIES})
    chosen = select_rules(manifest, RuleFilter())

    written = extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert len(written) == len(ENTRIES)
    assert all(path.is_file() for path in written)


def test_an_entry_the_manifest_does_not_declare_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    _, manifest = pack(ENTRIES)
    data = archive_of({**ENTRIES, "S3.C99/metadata.json": b"{}"})
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert caught.value.code == "archive_mismatch"
    assert list(tmp_path.iterdir()) == []


def test_a_declared_file_missing_from_the_archive_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    _, manifest = pack(ENTRIES)
    data = archive_of({k: v for k, v in ENTRIES.items() if not k.endswith(".rego")})
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert caught.value.code == "archive_mismatch"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "name",
    ["", "/abs/x", "../x", "a/../x", "a/./x", "a//b", "a\\b", "C:x", "a/b:c"],
)
def test_the_name_guard_refuses_a_name_that_could_leave_its_folder(name: str) -> None:
    assert not _is_safe(name)


@pytest.mark.parametrize(
    "name",
    ["S3.C20/metadata.json", "S3.C20/allowlist/cloud/check.rego", "S3.C20/a..b/c"],
)
def test_the_name_guard_accepts_a_name_inside_its_folder(name: str) -> None:
    assert _is_safe(name)


@pytest.mark.parametrize(
    "name",
    ["../escape.rego", "/abs/escape.rego", "S3.C20//x.rego", "S3.C20/C:x.rego"],
)
def test_a_declared_entry_that_could_leave_its_folder_is_refused(
    tmp_path: pathlib.Path, name: str
) -> None:
    # The manifest declares the name, so the undeclared-entry check has nothing
    # to refuse and only the name guard stands between the entry and the disk.
    data, manifest = pack({**ENTRIES, name: b"x"})
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "rules",
    [
        [
            rule(
                "S3.C20",
                ["allowlist"],
                files=["metadata.json", "metadata.json", "allowlist/cloud/check.rego"],
            ),
            rule("S3.C21", ["allowlist"], files=["metadata.json"]),
        ],
        [
            rule(
                "S3.C20",
                ["allowlist"],
                files=["metadata.json", "allowlist/cloud/check.rego"],
            ),
            rule("S3.C20", ["allowlist"], files=["metadata.json"]),
            rule("S3.C21", ["allowlist"], files=["metadata.json"]),
        ],
    ],
    ids=["file-twice", "rule-twice"],
)
def test_a_path_the_manifest_lists_twice_refuses_the_pack(
    tmp_path: pathlib.Path, rules: list[dict[str, Any]]
) -> None:
    data = archive_of(ENTRIES)
    manifest = manifest_for(data, rules)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "bad_manifest"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "entries",
    [
        {
            "S3.C20/a.rego": b"lower",
            "S3.C20/A.rego": b"UPPER",
            "S3.C20/z.rego": b"z",
        },
        {"S3.C20/metadata.json": b"{}", "s3.c20/metadata.json": b"{}"},
        {"S3.C20/allowlist": b"a file", "S3.C20/allowlist/cloud/x.rego": b"x"},
        {"S3.C20/Allowlist": b"a file", "S3.C20/allowlist/cloud/x.rego": b"x"},
    ],
    ids=["file-case", "rule-case", "file-and-folder", "file-and-folder-case"],
)
def test_names_that_land_on_one_path_refuse_the_pack(
    tmp_path: pathlib.Path, entries: dict[str, bytes]
) -> None:
    data, manifest = pack(entries)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "file",
    [
        "what?.md",
        "x.rego.",
        "x.rego ",
        "con.txt",
        "NUL",
        "lpt1",
        "dir/aux/x.rego",
        "a<b",
        "a>b",
        'a"b',
        "a|b",
        "a*b",
        "a\x01b",
    ],
)
def test_a_name_windows_cannot_write_refuses_the_pack_on_every_platform(
    tmp_path: pathlib.Path, file: str
) -> None:
    data, manifest = pack({**ENTRIES, f"S3.C20/{file}": b"x"})
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


def test_a_name_windows_cannot_write_is_harmless_when_it_is_not_selected(
    tmp_path: pathlib.Path,
) -> None:
    data, manifest = pack({**ENTRIES, "S3.C20/what?.md": b"x"})
    chosen = select_rules(manifest, RuleFilter(controls=("S3.C21",)))

    written = extract(data, manifest, "aws-s3", chosen, tmp_path)

    assert written == [tmp_path / "aws-s3" / "S3.C21" / "metadata.json"]


def retagged(data: bytes, *, method: int | None = None, flags: int = 0) -> bytes:
    """Rewrite the method and flag bits in every entry header of a zip.

    Args:
        data: The zip.
        method: The compression method to declare, or None to keep each one.
        flags: General purpose bits to set.

    Returns:
        The zip, with its local and central headers changed to match.
    """
    out = bytearray(data)
    # Each header is (signature, flags offset, method offset).
    for signature, flags_at, method_at in (
        (b"PK\x03\x04", 6, 8),
        (b"PK\x01\x02", 8, 10),
    ):
        at = out.find(signature)
        while at >= 0:
            (current,) = struct.unpack_from("<H", out, at + flags_at)
            struct.pack_into("<H", out, at + flags_at, current | flags)
            if method is not None:
                struct.pack_into("<H", out, at + method_at, method)
            at = out.find(signature, at + 4)
    return bytes(out)


def with_data_byte(data: bytes, at: int, value: bytes) -> bytes:
    """Overwrite one byte of the first entry's stored data.

    Args:
        data: The zip.
        at: The byte's offset from the start of that entry's data.
        value: The byte to write.

    Returns:
        The zip, damaged.
    """
    start = 30 + len("S3.C20/metadata.json") + at
    return data[:start] + value + data[start + 1 :]


def with_central_directory_moved(data: bytes, by: int) -> bytes:
    """Make the end record overstate where the central directory starts.

    ``zipfile`` takes the gap between that offset and the real one for bytes
    prepended to the archive, so every entry then looks to start before the
    first byte and reading one seeks to a negative position.

    Args:
        data: The zip.
        by: How many bytes to add to the declared offset.

    Returns:
        The zip, with its end record changed.
    """
    out = bytearray(data)
    end = out.rfind(b"PK\x05\x06")
    (offset,) = struct.unpack_from("<I", out, end + 16)
    struct.pack_into("<I", out, end + 16, offset + by)
    return bytes(out)


def with_invalid_utf8_name(data: bytes, header: str) -> bytes:
    """Declare the first entry's name to be UTF-8 and make it invalid.

    Args:
        data: The zip.
        header: ``local`` to change the header that precedes the entry's data,
            or ``central`` to change its record in the central directory.

    Returns:
        The zip, with the flag set and the first byte of that name replaced by
        ``0xFF``, which no UTF-8 text can start with.
    """
    signature, flags_at, name_at = {
        "local": (b"PK\x03\x04", 6, 30),
        "central": (b"PK\x01\x02", 8, 46),
    }[header]
    out = bytearray(data)
    at = out.find(signature)
    (current,) = struct.unpack_from("<H", out, at + flags_at)
    struct.pack_into("<H", out, at + flags_at, current | 0x800)
    out[at + name_at] = 0xFF
    return bytes(out)


@pytest.mark.parametrize(
    "damaged",
    [
        b"this is not a zip",
        archive_of(ENTRIES)[:-30],
        archive_of(ENTRIES)[:70],
        archive_of(ENTRIES).replace(b"package a", b"package b"),
        retagged(archive_of(ENTRIES), flags=0x1),
        retagged(archive_of(ENTRIES), method=99),
        with_data_byte(archive_of(ENTRIES, zipfile.ZIP_DEFLATED), 0, b"\xff"),
        with_data_byte(archive_of(ENTRIES, zipfile.ZIP_BZIP2), 0, b"\x00"),
        with_data_byte(archive_of(ENTRIES, zipfile.ZIP_LZMA), 4, b"\xff"),
        with_central_directory_moved(archive_of(ENTRIES), 10),
        with_invalid_utf8_name(archive_of(ENTRIES), "central"),
        with_invalid_utf8_name(archive_of(ENTRIES), "local"),
    ],
    ids=[
        "not-a-zip",
        "cut-in-the-end-record",
        "cut-in-the-first-entry",
        "bad-crc",
        "encrypted",
        "unsupported",
        "deflate",
        "bzip2",
        "lzma",
        "central-directory-offset",
        "central-name-encoding",
        "local-name-encoding",
    ],
)
def test_an_archive_the_client_cannot_read_refuses_the_pack(
    tmp_path: pathlib.Path, damaged: bytes
) -> None:
    _, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(damaged, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unreadable"
    assert list(tmp_path.iterdir()) == []


def test_an_entry_that_ends_early_refuses_the_pack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # zipfile raises EOFError when a member's data ends before its declared
    # size, which no archive this module can build reproduces on purpose.
    def ends_early(self: zipfile.ZipFile, name: str, pwd: bytes | None = None) -> bytes:
        raise EOFError

    monkeypatch.setattr(zipfile.ZipFile, "read", ends_early)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unreadable"
    assert list(tmp_path.iterdir()) == []


def tree(root: pathlib.Path) -> dict[str, bytes | None]:
    """Record every file and folder under a root.

    Args:
        root: The folder to walk.

    Returns:
        Each path relative to the root, mapped to its content, or None for a
        folder.
    """
    return {
        path.relative_to(root).as_posix(): path.read_bytes() if path.is_file() else None
        for path in sorted(root.rglob("*"))
    }


def fail_moves(
    monkeypatch: pytest.MonkeyPatch,
    refuses: Callable[[pathlib.Path, pathlib.Path], bool],
    error: type[BaseException] = PermissionError,
) -> None:
    """Make os.replace fail for the moves a test picks.

    Args:
        monkeypatch: The test's monkeypatch.
        refuses: Decides from a move's source and target whether it fails.
        error: What the failing move raises.
    """
    real = os.replace

    def replace(src: Any, dst: Any) -> None:
        if refuses(pathlib.Path(src), pathlib.Path(dst)):
            raise error(13, "The file is in use", str(dst))
        real(src, dst)

    monkeypatch.setattr(os, "replace", replace)


def fail_placing(monkeypatch: pytest.MonkeyPatch, *tail: str) -> None:
    """Make os.replace fail when it would move a file to a given place.

    Args:
        monkeypatch: The test's monkeypatch.
        tail: The last parts of the path the failing move targets.
    """
    fail_moves(monkeypatch, lambda src, dst: dst.parts[-len(tail) :] == tail)


def test_a_move_that_fails_part_way_leaves_nothing_behind(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())
    fail_placing(monkeypatch, "aws-s3", "S3.C21", "metadata.json")

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, PermissionError)
    assert list(tmp_path.iterdir()) == []


def test_a_move_that_fails_part_way_restores_what_was_there(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    (out / "notes.txt").write_bytes(b"not part of any pack")
    before = tree(out)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())
    fail_placing(monkeypatch, "aws-s3", "S3.C21", "metadata.json")

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    assert caught.value.code == "archive_unwritable"
    assert tree(out) == before


def test_a_read_only_file_from_an_earlier_fetch_is_replaced_without_a_trace(
    tmp_path: pathlib.Path,
) -> None:
    out = tmp_path / "out"
    target = out / "aws-s3" / "S3.C20" / "allowlist" / "cloud" / "check.rego"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"from an earlier fetch")
    target.chmod(stat.S_IREAD)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter(controls=("S3.C20",)))

    extract(data, manifest, "aws-s3", chosen, out)

    # The old copy is set aside in the staging folder, which Windows cannot
    # delete while the copy is read-only, so a hidden folder of stale files
    # would be left in the output folder after a fetch that succeeded.
    assert target.read_bytes() == b"package a"
    assert sorted(path.name for path in out.iterdir()) == ["aws-s3"]


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Only Windows refuses to move a file that another program has open.",
)
def test_a_file_another_program_holds_open_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    (earlier / "allowlist" / "cloud").mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    held = earlier / "allowlist" / "cloud" / "check.rego"
    held.write_bytes(b"open in an editor")
    before = tree(out)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    with held.open("rb"), pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    # The first file was already replaced when the second could not be moved.
    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, PermissionError)
    assert tree(out) == before


def test_an_interrupt_part_way_through_the_moves_restores_what_was_there(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    before = tree(out)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())
    fail_moves(
        monkeypatch,
        lambda src, dst: dst.parts[-3:] == ("aws-s3", "S3.C21", "metadata.json"),
        error=KeyboardInterrupt,
    )

    # An interrupt propagates as itself and never becomes a failed pack, and it
    # must leave the pack as it was all the same.
    with pytest.raises(KeyboardInterrupt):
        extract(data, manifest, "aws-s3", chosen, out)

    assert tree(out) == before


def test_a_failed_restore_keeps_the_only_copy_of_the_file_it_replaced(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())
    # The move that fails, and then every move out of the folder holding what
    # was set aside, so the restore fails as well.
    fail_moves(
        monkeypatch,
        lambda src, dst: (
            dst.parts[-3:] == ("aws-s3", "S3.C21", "metadata.json")
            or "old" in src.parts
        ),
    )

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    (staging,) = [path for path in out.iterdir() if path.name.startswith(".aws-s3-")]
    assert (staging / "old" / "0").read_bytes() == b"from an earlier fetch"
    assert caught.value.code == "archive_unwritable"
    assert str(staging) in str(caught.value)


def test_a_folder_where_a_file_belongs_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    blocked = out / "aws-s3" / "S3.C21" / "metadata.json"
    blocked.mkdir(parents=True)
    (blocked / "notes.txt").write_bytes(b"kept by someone else")
    before = tree(out)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    assert caught.value.code == "archive_unwritable"
    assert "S3.C21" in str(caught.value)
    assert tree(out) == before


def test_a_file_where_a_folder_belongs_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    (out / "aws-s3" / "S3.C21").write_bytes(b"a file where a folder belongs")
    before = tree(out)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    # The disk's own refusal comes from the first move into the missing folder,
    # after the rule before it has already been laid out, so putting it all back
    # is what leaves the earlier fetch intact.
    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, OSError)
    assert tree(out) == before


def test_a_member_that_fails_after_good_ones_leaves_the_folder_as_it_was(
    tmp_path: pathlib.Path,
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    before = tree(out)
    entries = {**ENTRIES, "S3.C21/metadata.json": b"21 is fine"}
    _, manifest = pack(entries)
    # The same length, so only the entry's CRC no longer matches its content.
    data = archive_of(entries).replace(b"21 is fine", b"21 is FINE")
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    # Two members were already staged when the third failed to read, so this
    # fails if the staging folder is left behind or a file reaches its place.
    assert caught.value.code == "archive_unreadable"
    assert tree(out) == before

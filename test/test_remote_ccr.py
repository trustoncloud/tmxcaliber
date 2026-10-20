"""Selecting CCR rules from a manifest, and writing them from an archive."""

from __future__ import annotations

import errno
import hashlib
import io
import os
import pathlib
import stat
import struct
import sys
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from tmxcaliber.lib.remote.ccr import (
    MATCHERS,
    MODES,
    PackFailure,
    RuleFilter,
    _is_safe,
    extract,
    fetch,
    rule_row,
    select_rules,
    verify_archive,
)
from tmxcaliber.lib.remote.errors import (
    AuthenticationError,
    ContractViolation,
    NoPackMatched,
    NotFound,
    RateLimited,
    ReleaseSuperseded,
    RemoteError,
    ServiceUnavailable,
)


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


#: A release id as the API issues it, which is the commit the pack was built
#: from (``GITHUB_SHA``), so 40 characters where most fixtures here use 8.
FULL_RELEASE = "d07d6aee5f3c9b1e8a4d2c6b0f7e9a1d3c5b7e2f"


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


def test_a_row_carries_a_full_length_release_id_whole() -> None:
    # Seven characters are enough to tell releases apart on screen, but the row
    # is what a script pins the next request to, so it carries the whole id.
    [chosen] = select_rules(MANIFEST, RuleFilter(controls=("S3.C21",)))

    assert rule_row("aws-s3", FULL_RELEASE, chosen)["releaseId"] == FULL_RELEASE


def test_a_rule_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ContractViolation):
        select_rules({"rules": ["S3.C20"]}, RuleFilter())


@pytest.mark.parametrize(
    ("fields", "named"),
    [
        ({"modes": ("Universal",)}, ("'Universal'", *MODES)),
        ({"modes": ("allowlist", "sometimes")}, ("'sometimes'", *MODES)),
        ({"matchers": ("clouds",)}, ("'clouds'", *MATCHERS)),
    ],
    ids=["capitalised mode", "one unknown mode of two", "misspelled matcher"],
)
def test_a_mode_or_matcher_no_rule_can_have_is_refused(
    fields: dict[str, tuple[str, ...]], named: tuple[str, ...]
) -> None:
    # It would select nothing, and an empty answer reads as a pack with no
    # such rule rather than as a typing slip.
    with pytest.raises(ValueError) as refused:
        RuleFilter(**fields)

    for text in named:
        assert text in str(refused.value)


def test_every_published_mode_and_matcher_is_accepted() -> None:
    wanted = RuleFilter(modes=MODES, matchers=MATCHERS)

    assert (wanted.modes, wanted.matchers) == (MODES, MATCHERS)


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


@pytest.mark.parametrize(
    "where",
    [
        "out-is-a-file",
        "out-is-below-a-file",
        pytest.param(
            "out-has-an-invalid-name",
            marks=pytest.mark.skipif(
                sys.platform != "win32",
                reason="Only Windows refuses a question mark in a folder name.",
            ),
        ),
    ],
)
def test_an_output_folder_the_disk_refuses_refuses_the_pack(
    tmp_path: pathlib.Path, where: str
) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"a file where the output folder belongs")
    out = {
        "out-is-a-file": blocker,
        "out-is-below-a-file": blocker / "out",
        "out-has-an-invalid-name": tmp_path / "out?",
    }[where]
    before = tree(tmp_path)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    # fetch can only go on to the next pack when this arrives as a failed pack,
    # so a raw OSError here would end a whole fetch with a traceback.
    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, OSError)
    assert tree(tmp_path) == before


@pytest.mark.parametrize("out_exists", [True, False], ids=["out-exists", "out-is-new"])
def test_a_staging_folder_the_disk_refuses_leaves_the_output_as_it_was(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, out_exists: bool
) -> None:
    out = tmp_path / "out"
    if out_exists:
        earlier = out / "aws-s3" / "S3.C20"
        earlier.mkdir(parents=True)
        (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    before = tree(tmp_path)

    def refuse(*args: Any, **kwargs: Any) -> str:
        raise PermissionError(13, "Permission denied", str(out))

    monkeypatch.setattr(tempfile, "mkdtemp", refuse)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    # On POSIX this is what an output folder the user cannot write gives. When
    # the folder is new, extract has already made it by then, and must take it
    # out again.
    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, PermissionError)
    assert tree(tmp_path) == before


def test_a_pack_folder_that_cannot_be_searched_refuses_the_pack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    before = tree(out)
    real = pathlib.Path.is_dir

    def is_dir(self: pathlib.Path, *args: Any, **kwargs: Any) -> bool:
        if self.parts[-3:] == ("aws-s3", "S3.C21", "metadata.json"):
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *args, **kwargs)

    # Python 3.10 to 3.12 raise this from Path.is_dir for a folder the user
    # cannot search, such as one an earlier run as root left behind.
    monkeypatch.setattr(pathlib.Path, "is_dir", is_dir)
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, PermissionError)
    assert "S3.C21" in str(caught.value)
    assert tree(out) == before


@pytest.mark.parametrize(
    "file",
    [
        "../escape.rego",
        "../../../escape.rego",
        "allowlist/../x.rego",
        "/abs.rego",
        "a//b.rego",
        "C:x.rego",
    ],
)
def test_a_selected_path_that_could_leave_its_folder_is_refused_unread(
    tmp_path: pathlib.Path, file: str
) -> None:
    # The archive is honest and lacks the file, so the missing-file check would
    # refuse this pack with another code. Only a check on the manifest's own
    # paths, the strings that reach the disk, gives archive_unsafe.
    data = archive_of(ENTRIES)
    manifest = manifest_for(
        data,
        [
            rule("S3.C20", ["allowlist"], files=["metadata.json", file]),
            rule("S3.C21", ["allowlist"], files=["metadata.json"]),
        ],
    )
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


#: Stands for a key that is an absolute path, which only the test can build,
#: because it has to lie under the test's own folder.
ABSOLUTE_KEY = "<an absolute path>"


@pytest.mark.parametrize(
    "key",
    [
        "..",
        ".",
        "",
        "../x",
        "../../sibling",
        "a/b",
        "a\\b",
        "aws-s3/..",
        "aws-s3\n",
        "aws\0s3",
        "AWS-S3",
        "awss3",
        "-aws",
        "aws-",
        "aws--s3",
        ABSOLUTE_KEY,
    ],
    ids=[
        "parent",
        "current",
        "empty",
        "parent-then-name",
        "two-levels-up",
        "separator",
        "backslash",
        "name-then-parent",
        "trailing-newline",
        "null-byte",
        "uppercase",
        "no-hyphen",
        "leading-hyphen",
        "trailing-hyphen",
        "doubled-hyphen",
        "absolute",
    ],
)
def test_a_release_key_that_could_leave_the_output_folder_is_refused_unread(
    tmp_path: pathlib.Path, key: str
) -> None:
    # The key is joined onto ``out`` as a folder name, and it reaches this
    # client from the API with nothing between it and the disk. The archive is
    # honest and its one file is safe under every check on names, so only a
    # check on the key refuses this pack. With the key ``..`` the file would
    # replace one that belongs to a sibling of ``out``.
    if key == ABSOLUTE_KEY:
        key = str(tmp_path / "elsewhere")
    home = tmp_path / "home"
    owned = home / ".ssh" / "authorized_keys"
    owned.parent.mkdir(parents=True)
    owned.write_bytes(b"owner")
    data, manifest = pack({".ssh/authorized_keys": b"attacker"})
    chosen = select_rules(manifest, RuleFilter())
    before = tree(tmp_path)

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, key, chosen, home / "ccr")

    assert caught.value.code == "archive_unsafe"
    assert tree(tmp_path) == before
    assert owned.read_bytes() == b"owner"


@pytest.mark.parametrize(
    "key", ["aws-s3", "gcp-cloud-storage", "azure-key-vault-2", "a-1"]
)
def test_a_release_key_in_the_servers_form_is_written_under_its_own_folder(
    tmp_path: pathlib.Path, key: str
) -> None:
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())

    written = extract(data, manifest, key, chosen, tmp_path / "out")

    assert written
    assert all((tmp_path / "out" / key) in path.parents for path in written)


def test_a_name_that_zipfile_cuts_short_refuses_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    # zipfile ends a name at its first null byte, so the name it reports and
    # the name the archive stores are two strings, and the checks on the stored
    # one say nothing about the one that is read and written. The manifest
    # declares the short name, so nothing else refuses this pack.
    placeholder = "S3.C20/notes.md#xxxx"
    stored = "S3.C20/notes.md\0xxxx"
    data = with_raw_name(
        archive_of({**ENTRIES, placeholder: b"x"}), placeholder, stored
    )
    declared = pack({**ENTRIES, "S3.C20/notes.md": b"x"})[1]["rules"]
    manifest = manifest_for(data, declared)
    chosen = select_rules(manifest, RuleFilter())

    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


def test_a_backslash_in_a_folder_entry_is_ignored_on_every_platform(
    tmp_path: pathlib.Path,
) -> None:
    # zipfile folds the backslash on Windows and keeps it elsewhere, so a check
    # that compares the reported name with the stored one without setting the
    # backslash aside would refuse this archive on one platform only. A folder
    # entry is never written, so it has nothing to refuse.
    placeholder = "S3.C20/sub/"
    stored = "S3.C20\\sub/"
    data = with_raw_name(archive_of({**ENTRIES, placeholder: b""}), placeholder, stored)
    manifest = manifest_for(data, pack(ENTRIES)[1]["rules"])
    chosen = select_rules(manifest, RuleFilter())

    written = extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert len(written) == len(ENTRIES)


def with_unicode_path(entries: dict[str, bytes], name: str, renamed: str) -> bytes:
    """Zip entries, giving one a Unicode Path extra field that renames it.

    The extra field (0x7075) carries a UTF-8 name and the CRC of the name
    stored in the header, and a reader that honours it reports the new name.

    Args:
        entries: Each entry name and its content.
        name: The entry to rename.
        renamed: The name its extra field gives it.

    Returns:
        The zip, in which the entry is stored under ``name``.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for entry, content in entries.items():
            info = zipfile.ZipInfo(entry)
            if entry == name:
                payload = struct.pack("<BL", 1, zlib.crc32(entry.encode()))
                payload += renamed.encode()
                info.extra = struct.pack("<HH", 0x7075, len(payload)) + payload
            archive.writestr(info, content)
    return buffer.getvalue()


@pytest.mark.parametrize(
    "renamed",
    ["S3.C20/renamed.rego", "S3.C20/../../../escape.rego"],
    ids=["a-safe-name", "a-name-that-leaves-the-folder"],
)
def test_a_name_that_an_extra_field_changes_refuses_the_pack(
    tmp_path: pathlib.Path, renamed: str
) -> None:
    entries = {**ENTRIES, "S3.C20/stored.rego": b"x"}
    data = with_unicode_path(entries, "S3.C20/stored.rego", renamed)
    reported = {info.filename for info in zipfile.ZipFile(io.BytesIO(data)).infolist()}
    if "S3.C20/stored.rego" in reported:
        pytest.skip("This zipfile ignores the Unicode Path extra field.")
    declared = pack({**ENTRIES, renamed: b"x"})[1]["rules"]
    manifest = manifest_for(data, declared)
    chosen = select_rules(manifest, RuleFilter())

    # The stored name is safe and the name that is read and written is the one
    # the manifest declares, so the pack is refused for the two disagreeing.
    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, tmp_path / "out")

    assert caught.value.code == "archive_unsafe"
    assert list(tmp_path.iterdir()) == []


def fail_deleting_staging(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every delete inside the staging folder fail with an I/O error.

    Args:
        monkeypatch: The test's monkeypatch.
    """
    real = os.unlink

    def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if ".aws-s3-" in str(path):
            raise OSError(errno.EIO, "Input/output error", str(path))
        real(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)


def test_a_staging_folder_that_cannot_be_deleted_does_not_hide_why_the_pack_failed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    earlier = out / "aws-s3" / "S3.C20"
    earlier.mkdir(parents=True)
    (earlier / "metadata.json").write_bytes(b"from an earlier fetch")
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())
    fail_placing(monkeypatch, "aws-s3", "S3.C21", "metadata.json")
    fail_deleting_staging(monkeypatch)

    # The delete runs while the move's failure is propagating, so an error from
    # it would take the place of that failure and reach fetch as a raw OSError.
    with pytest.raises(ContractViolation) as caught:
        extract(data, manifest, "aws-s3", chosen, out)

    assert caught.value.code == "archive_unwritable"
    assert isinstance(caught.value.__cause__, PermissionError)
    assert (earlier / "metadata.json").read_bytes() == b"from an earlier fetch"


def test_a_staging_folder_that_cannot_be_deleted_does_not_fail_a_pack_that_was_written(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    target = out / "aws-s3" / "S3.C20" / "metadata.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"from an earlier fetch")
    data, manifest = pack(ENTRIES)
    chosen = select_rules(manifest, RuleFilter())
    fail_deleting_staging(monkeypatch)

    written = extract(data, manifest, "aws-s3", chosen, out)

    # The old copy was set aside in the staging folder, which stays behind
    # because it cannot be deleted. The files are all in place by then.
    assert len(written) == len(ENTRIES)
    assert target.read_bytes() == b"{}"


class PackClient:
    """Answers the three CCR routes from fixtures, and records every call."""

    def __init__(self, packs: dict[str, tuple[bytes, dict[str, Any]]]) -> None:
        self.packs = packs
        self.calls: list[tuple[str, dict[str, str]]] = []
        #: Release keys whose next archive call answers 410 once.
        self.supersede_once: set[str] = set()
        #: Release keys whose archive call raises this error, as the client
        #: raises it once its own retries are spent.
        self.archive_errors: dict[str, RemoteError] = {}

    def paginate(
        self, path: str, params: Mapping[str, str] | None = None, **_: Any
    ) -> Any:
        self.calls.append((path, dict(params or {})))
        yield from ({"releaseKey": key} for key in sorted(self.packs))

    def get(self, path: str, params: Mapping[str, str] | None = None) -> dict[str, Any]:
        self.calls.append((path, dict(params or {})))
        key = path.rsplit("/", 1)[-1]
        if key not in self.packs:
            raise NotFound("No such pack.", code="not_found", status=404)
        return self.packs[key][1]

    def get_bytes(self, path: str, params: Mapping[str, str] | None = None) -> bytes:
        self.calls.append((path, dict(params or {})))
        key = path.split("/")[-2]
        if key in self.archive_errors:
            raise self.archive_errors[key]
        if key in self.supersede_once:
            self.supersede_once.discard(key)
            raise ReleaseSuperseded(
                "Superseded.", code="release_superseded", status=410
            )
        return self.packs[key][0]


def two_packs() -> dict[str, tuple[bytes, dict[str, Any]]]:
    """Two packs, one per provider.

    Returns:
        Each pack's archive and manifest, by release key.
    """
    return {
        "aws-s3": pack(ENTRIES),
        "gcp-bigquery": pack({"Bigquery.C102/metadata.json": b"{}"}),
    }


def test_without_out_no_archive_is_downloaded() -> None:
    client = PackClient(two_packs())

    result = fetch(client, wanted=RuleFilter(controls=("S3.C20",)))  # type: ignore[arg-type]

    assert [row["ruleId"] for row in result.rows] == ["S3.C20"]
    assert not any(path.endswith("/archive") for path, _ in client.calls)


def test_provider_and_service_narrow_the_listed_packs() -> None:
    client = PackClient(two_packs())

    result = fetch(client, providers=("gcp",))  # type: ignore[arg-type]

    assert {row["releaseKey"] for row in result.rows} == {"gcp-bigquery"}
    assert ("/v1/ccr/packs/aws-s3", {}) not in client.calls


def test_named_packs_are_read_without_listing() -> None:
    client = PackClient(two_packs())

    fetch(client, release_keys=("aws-s3",))  # type: ignore[arg-type]

    assert client.calls == [("/v1/ccr/packs/aws-s3", {})]


def test_naming_packs_and_narrowing_them_is_refused() -> None:
    with pytest.raises(ValueError):
        fetch(PackClient({}), release_keys=("aws-s3",), providers=("aws",))  # type: ignore[arg-type]


def test_only_packs_with_a_match_are_downloaded_pinned_to_their_release(
    tmp_path: pathlib.Path,
) -> None:
    client = PackClient(two_packs())

    result = fetch(client, wanted=RuleFilter(controls=("S3.C20",)), out=tmp_path)  # type: ignore[arg-type]

    archives = [(p, q) for p, q in client.calls if p.endswith("/archive")]
    assert archives == [
        ("/v1/ccr/packs/aws-s3/archive", {"kind": "source", "release": "d07d6aee"})
    ]
    assert result.written == [
        tmp_path / "aws-s3" / "S3.C20" / "metadata.json",
        tmp_path / "aws-s3" / "S3.C20" / "allowlist" / "cloud" / "check.rego",
    ]


def test_a_full_length_release_id_pins_the_archive_and_fills_every_row(
    tmp_path: pathlib.Path,
) -> None:
    packs = two_packs()
    data, manifest = packs["aws-s3"]
    packs["aws-s3"] = (data, {**manifest, "release_id": FULL_RELEASE})
    client = PackClient(packs)

    result = fetch(client, release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    archives = [query for path, query in client.calls if path.endswith("/archive")]
    assert archives == [{"kind": "source", "release": FULL_RELEASE}]
    assert [row["releaseId"] for row in result.rows] == [FULL_RELEASE] * 2
    assert len(result.written) == len(ENTRIES)


def test_a_superseded_release_is_read_again_once(tmp_path: pathlib.Path) -> None:
    client = PackClient(two_packs())
    client.supersede_once.add("aws-s3")

    result = fetch(client, release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    assert result.failed == {}
    assert [p for p, _ in client.calls].count("/v1/ccr/packs/aws-s3") == 2


def test_one_failed_pack_does_not_stop_the_others(tmp_path: pathlib.Path) -> None:
    packs = two_packs()
    data, manifest = packs["aws-s3"]
    packs["aws-s3"] = (data + b"tampered", manifest)
    client = PackClient(packs)

    result = fetch(client, out=tmp_path)  # type: ignore[arg-type]

    assert set(result.failed) == {"aws-s3"}
    failure = result.failed["aws-s3"]
    assert (failure.stage, failure.code) == ("verify", "archive_mismatch")
    assert failure.release_id == "d07d6aee"
    assert (tmp_path / "gcp-bigquery" / "Bigquery.C102" / "metadata.json").exists()
    assert not (tmp_path / "aws-s3").exists()


def test_an_unknown_named_pack_is_reported_not_raised() -> None:
    result = fetch(PackClient(two_packs()), release_keys=("aws-nothing",))  # type: ignore[arg-type]

    failure = result.failed["aws-nothing"]
    assert (failure.stage, failure.code, failure.status) == (
        "manifest",
        "not_found",
        404,
    )
    # The manifest was never read, so there is no release to name.
    assert failure.release_id is None


def readable_packs(*extra: str) -> dict[str, tuple[bytes, dict[str, Any]]]:
    """The two packs, and more that the key can read.

    Args:
        *extra: More release keys, each a pack with one rule.

    Returns:
        Each pack's archive and manifest, by release key.
    """
    packs = two_packs()
    for key in extra:
        packs[key] = pack({f"{key.title()}.C1/metadata.json": b"{}"})
    return packs


def list_reads(client: PackClient) -> int:
    """Count how often a fetch read the pack list.

    Args:
        client: The client the fetch used.

    Returns:
        The number of ``ccr packs list`` calls.
    """
    return [path for path, _ in client.calls].count("/v1/ccr/packs")


def test_an_unknown_named_pack_suggests_a_pack_the_key_can_read() -> None:
    client = PackClient(readable_packs("aws-ec2"))

    result = fetch(client, release_keys=("ec3",))  # type: ignore[arg-type]

    failure = result.failed["ec3"]
    assert failure.suggestions == ("aws-ec2",)
    assert str(failure) == (
        "manifest failed: No such pack. [not_found, HTTP 404]. "
        f"{UNKNOWN_HINT} Did you mean aws-ec2?"
    )


def test_the_pack_list_is_read_once_however_many_named_packs_are_unknown() -> None:
    client = PackClient(readable_packs("aws-ec2"))

    result = fetch(client, release_keys=("ec3", "aws-s4", "aws-s3"))  # type: ignore[arg-type]

    assert list_reads(client) == 1
    assert result.failed["ec3"].suggestions == ("aws-ec2",)
    assert result.failed["aws-s4"].suggestions[0] == "aws-s3"
    assert {row["releaseKey"] for row in result.rows} == {"aws-s3"}


def test_the_pack_list_is_not_read_when_every_named_pack_is_known(
    tmp_path: pathlib.Path,
) -> None:
    # A pack can fail at a later stage, or for another reason than being
    # unknown, and neither is a name to correct.
    packs = readable_packs("aws-ec2")
    data, manifest = packs["aws-s3"]
    packs["aws-s3"] = (data, {**manifest, "rules": ["S3.C20"]})
    client = PackClient(packs)
    client.archive_errors["gcp-bigquery"] = NotFound(
        "Withdrawn.", code="not_found", status=404
    )

    result = fetch(  # type: ignore[arg-type]
        client, release_keys=("aws-s3", "gcp-bigquery", "aws-ec2"), out=tmp_path
    )

    assert list_reads(client) == 0
    assert (result.failed["aws-s3"].stage, result.failed["aws-s3"].code) == (
        "manifest",
        "bad_manifest",
    )
    assert (
        result.failed["gcp-bigquery"].stage,
        result.failed["gcp-bigquery"].code,
    ) == ("archive", "not_found")
    assert all(failure.suggestions == () for failure in result.failed.values())


class Unlisted(PackClient):
    """A client whose pack list fails, while each pack still answers."""

    def __init__(
        self, packs: dict[str, tuple[bytes, dict[str, Any]]], error: RemoteError
    ) -> None:
        super().__init__(packs)
        self.error = error

    def paginate(
        self, path: str, params: Mapping[str, str] | None = None, **_: Any
    ) -> Any:
        self.calls.append((path, dict(params or {})))
        raise self.error


@pytest.mark.parametrize(
    "error",
    [
        ServiceUnavailable("Try later.", code="unavailable", status=503),
        RateLimited("Slow down.", retry_after=3600, code="rate_limited", status=429),
    ],
    ids=["outage", "rate limit"],
)
def test_a_pack_list_that_cannot_be_read_leaves_the_fetch_as_it_was(
    error: RemoteError,
) -> None:
    # The suggestion is a courtesy, so failing to read the list must not cost
    # the caller the packs that did answer.
    client = Unlisted(readable_packs("aws-ec2"), error)

    result = fetch(client, release_keys=("aws-s4", "ec3", "aws-s3"))  # type: ignore[arg-type]

    assert list_reads(client) == 1
    assert result.failed == {
        key: PackFailure(
            release_key=key,
            stage="manifest",
            code="not_found",
            message="No such pack.",
            status=404,
        )
        for key in ("aws-s4", "ec3")
    }
    assert {row["releaseKey"] for row in result.rows} == {"aws-s3"}


@pytest.mark.parametrize(
    ("narrowing", "message", "suggestions"),
    [
        pytest.param(
            {"services": ("gemini agent platform",)},
            "No pack this key can read matches --service 'gemini agent platform'. "
            "Did you mean gcp-vertex?",
            ("gcp-vertex",),
            id="renamed service",
        ),
        pytest.param(
            {"services": ("bigqeury",)},
            "No pack this key can read matches --service 'bigqeury'. "
            "Did you mean gcp-bigquery?",
            ("gcp-bigquery",),
            id="misspelled service",
        ),
        pytest.param(
            {"providers": ("gpc",)},
            "No pack this key can read matches --provider 'gpc'. Did you mean gcp?",
            ("gcp",),
            id="misspelled provider",
        ),
        pytest.param(
            {"providers": ("aws",), "services": ("bigquery",)},
            "No pack this key can read matches --provider 'aws' and --service "
            "'bigquery'. Did you mean gcp-bigquery?",
            ("gcp-bigquery",),
            id="service of another provider",
        ),
        pytest.param(
            {"services": ("nothing", "lambda")},
            "No pack this key can read matches --service 'nothing' or 'lambda'.",
            (),
            id="nothing close",
        ),
        pytest.param(
            {"providers": ("azr",)},
            "No pack this key can read matches --provider 'azr'.",
            (),
            id="provider with no readable pack",
        ),
    ],
)
def test_a_narrowing_that_leaves_no_pack_is_refused_with_suggestions(
    narrowing: dict[str, tuple[str, ...]],
    message: str,
    suggestions: tuple[str, ...],
) -> None:
    client = PackClient(readable_packs("gcp-vertex"))

    with pytest.raises(NoPackMatched) as refused:
        fetch(client, **narrowing)  # type: ignore[arg-type]

    assert str(refused.value) == message
    assert refused.value.suggestions == suggestions
    assert refused.value.code == "no_pack_matched"
    # Nothing past the list was read, because no pack was left to read.
    assert [path for path, _ in client.calls] == ["/v1/ccr/packs"]


def test_a_narrowing_that_leaves_a_pack_is_not_refused() -> None:
    client = PackClient(readable_packs("gcp-vertex"))

    result = fetch(client, services=("nothing", "vertex"))  # type: ignore[arg-type]

    assert {row["releaseKey"] for row in result.rows} == {"gcp-vertex"}


def test_a_service_given_as_a_listed_release_key_reads_that_pack() -> None:
    # The provider is part of the key, so the key names the one pack, and the
    # service of any other pack that happens to share its tail stays out.
    client = PackClient(readable_packs("gcp-vertex", "aws-vertex"))

    result = fetch(client, services=("gcp-vertex",))  # type: ignore[arg-type]

    assert {row["releaseKey"] for row in result.rows} == {"gcp-vertex"}


def test_a_listed_release_key_still_obeys_the_provider_beside_it() -> None:
    client = PackClient(readable_packs("gcp-vertex"))

    with pytest.raises(NoPackMatched):
        fetch(client, providers=("aws",), services=("gcp-vertex",))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "typed",
    ["Gemini Agent Platform", "vertexai", "GCP-Vertex", "gemini-agent-platform"],
)
def test_the_pack_a_refused_service_suggests_can_be_given_back_as_the_service(
    typed: str,
) -> None:
    # The refusal says "Did you mean gcp-vertex?", and a person answers by
    # typing that into the same flag, so it has to be accepted there.
    client = PackClient(readable_packs("gcp-vertex"))

    with pytest.raises(NoPackMatched) as refused:
        fetch(client, services=(typed,))  # type: ignore[arg-type]
    [suggested] = refused.value.suggestions
    result = fetch(client, services=(suggested,))  # type: ignore[arg-type]

    assert suggested == "gcp-vertex"
    assert {row["releaseKey"] for row in result.rows} == {suggested}


def test_a_pack_the_key_cannot_read_is_never_suggested() -> None:
    # gcp-vertex is the alias's pack, and this key cannot read it, so naming it
    # would tell the caller about a pack outside their subscription.
    client = PackClient(two_packs())

    result = fetch(client, release_keys=("gemini-agent-platform",))  # type: ignore[arg-type]
    with pytest.raises(NoPackMatched) as refused:
        fetch(client, services=("gemini agent platform",))  # type: ignore[arg-type]

    assert result.failed["gemini-agent-platform"].suggestions == ()
    assert "Did you mean" not in str(result.failed["gemini-agent-platform"])
    assert refused.value.suggestions == ()
    assert "gcp-vertex" not in str(refused.value)


def test_a_pack_failure_with_suggestions_ends_with_them() -> None:
    failure = PackFailure(
        release_key="aws-ec3",
        stage="manifest",
        code="",
        message="Gone.",
        suggestions=("aws-ec2", "aws-s3"),
    )

    assert str(failure) == f"manifest failed: Gone. {failure.hint} " + (
        "Did you mean aws-ec2 or aws-s3?"
    )


def with_first_rule(manifest: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """Change some fields of a manifest's first rule.

    Args:
        manifest: The manifest.
        **fields: The fields to set on the first rule.

    Returns:
        A manifest whose first rule carries those fields.
    """
    first, *rest = manifest["rules"]
    return {**manifest, "rules": [{**first, **fields}, *rest]}


def without_first_rule_id(manifest: dict[str, Any]) -> dict[str, Any]:
    """Drop the id of a manifest's first rule.

    Args:
        manifest: The manifest.

    Returns:
        A manifest whose first rule has no ``id`` at all.
    """
    first, *rest = manifest["rules"]
    return {
        **manifest,
        "rules": [{k: v for k, v in first.items() if k != "id"}, *rest],
    }


#: The release the fixture manifest names. A refusal of anything but the release
#: id itself must still report it, because it tells support which published
#: release is broken.
NAMED_RELEASE = "d07d6aee"


def without_release(manifest: dict[str, Any]) -> dict[str, Any]:
    """Drop the release id of a manifest.

    Args:
        manifest: The manifest.

    Returns:
        A manifest that names no release at all.
    """
    return {name: value for name, value in manifest.items() if name != "release_id"}


#: Each wrong shape a manifest can take, the field its refusal must name, and the
#: release the failure must carry. That is the release the manifest names when
#: the manifest is an object and its release id is sound, and none otherwise.
MALFORMED = [
    pytest.param(lambda m: [m], "manifest", None, id="manifest is a list"),
    pytest.param(
        lambda m: {**m, "rules": {"S3.C20": m["rules"][0]}},
        "rules",
        NAMED_RELEASE,
        id="rules dict",
    ),
    pytest.param(
        lambda m: {**m, "rules": ["S3.C20"]},
        "rules[0]",
        NAMED_RELEASE,
        id="rule string",
    ),
    pytest.param(
        lambda m: {**m, "release_id": FULL_RELEASE, "rules": ["S3.C20"]},
        "rules[0]",
        FULL_RELEASE,
        id="rule string under a commit sha",
    ),
    pytest.param(
        lambda m: {**without_release(m), "rules": ["S3.C20"]},
        "rules[0]",
        None,
        id="rule string, no release named",
    ),
    pytest.param(without_first_rule_id, "rules[0].id", NAMED_RELEASE, id="id absent"),
    pytest.param(
        lambda m: with_first_rule(m, id=""),
        "rules[0].id",
        NAMED_RELEASE,
        id="id empty",
    ),
    pytest.param(
        lambda m: with_first_rule(m, id=20),
        "rules[0].id",
        NAMED_RELEASE,
        id="id number",
    ),
    pytest.param(
        lambda m: with_first_rule(m, modes="allowlist"),
        "rules[0].modes",
        NAMED_RELEASE,
        id="modes string",
    ),
    pytest.param(
        lambda m: with_first_rule(m, files="metadata.json"),
        "rules[0].files",
        NAMED_RELEASE,
        id="files string",
    ),
    pytest.param(
        lambda m: with_first_rule(m, files=["metadata.json", 7]),
        "rules[0].files",
        NAMED_RELEASE,
        id="files holds a number",
    ),
    pytest.param(
        lambda m: with_first_rule(m, matchers=["cloud"]),
        "rules[0].matchers",
        NAMED_RELEASE,
        id="matchers list",
    ),
    pytest.param(
        lambda m: with_first_rule(m, matchers={"cloud": True}),
        "rules[0].matchers",
        NAMED_RELEASE,
        id="matcher not an object",
    ),
    pytest.param(
        lambda m: {**m, "release_id": "D07D6AEE"},
        "release_id",
        None,
        id="release upper",
    ),
    pytest.param(
        lambda m: {**m, "release_id": "v1.2.3"},
        "release_id",
        None,
        id="release not hex",
    ),
    pytest.param(
        lambda m: {**m, "release_id": "d07d6a"},
        "release_id",
        None,
        id="release too short",
    ),
    pytest.param(
        lambda m: {**m, "release_id": "a" * 65},
        "release_id",
        None,
        id="release too long",
    ),
    pytest.param(
        lambda m: {**m, "release_id": "d07d6aee\n"},
        "release_id",
        None,
        id="release with a newline",
    ),
    pytest.param(
        lambda m: {**m, "release_id": 1234567},
        "release_id",
        None,
        id="release number",
    ),
    pytest.param(
        lambda m: {**m, "release_id": "D07D6AEE", "rules": ["S3.C20"]},
        "release_id",
        None,
        id="release refused before the rules are read",
    ),
]


@pytest.mark.parametrize(("malform", "field", "release"), MALFORMED)
def test_a_malformed_manifest_fails_only_its_own_pack(
    tmp_path: pathlib.Path,
    malform: Callable[[dict[str, Any]], Any],
    field: str,
    release: str | None,
) -> None:
    packs = two_packs()
    data, manifest = packs["aws-s3"]
    packs["aws-s3"] = (data, malform(manifest))
    client = PackClient(packs)

    result = fetch(client, out=tmp_path)  # type: ignore[arg-type]

    failure = result.failed["aws-s3"]
    assert (failure.stage, failure.code) == ("manifest", "bad_manifest")
    assert failure.message.startswith("aws-s3's manifest")
    assert field in failure.message
    # A refusal that follows the release id says which published release is
    # broken. Only a manifest that is no object, or whose id is itself refused,
    # has no release to name.
    assert failure.release_id == release
    if release:
        assert f", release {release[:7]}]" in str(failure)
    # A release id outside the API's form would draw a 400 that ends the whole
    # fetch, so the archive of a refused manifest is never asked for.
    assert "/v1/ccr/packs/aws-s3/archive" not in [path for path, _ in client.calls]
    assert result.written == [
        tmp_path / "gcp-bigquery" / "Bigquery.C102" / "metadata.json"
    ]
    assert not (tmp_path / "aws-s3").exists()


@pytest.mark.parametrize(
    ("second", "release"),
    [
        pytest.param(
            {"release_id": FULL_RELEASE, "rules": ["S3.C20"]},
            FULL_RELEASE,
            id="its own release",
        ),
        pytest.param(
            {"release_id": "D07D6AEE", "rules": ["S3.C20"]},
            None,
            id="no release, when its id is refused",
        ),
    ],
)
def test_a_republished_manifest_that_is_malformed_reports_its_own_release(
    tmp_path: pathlib.Path, second: dict[str, Any], release: str | None
) -> None:
    packs = two_packs()
    data, first = packs["aws-s3"]

    class Republished(PackClient):
        """Publishes a malformed manifest while the archive is being asked for."""

        def get_bytes(
            self, path: str, params: Mapping[str, str] | None = None
        ) -> bytes:
            try:
                return super().get_bytes(path, params)
            except ReleaseSuperseded:
                self.packs["aws-s3"] = (data, {**first, **second})
                raise

    client = Republished(packs)
    client.supersede_once.add("aws-s3")

    result = fetch(client, release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    failure = result.failed["aws-s3"]
    assert (failure.stage, failure.code) == ("manifest", "bad_manifest")
    # The first manifest's release no longer describes the pack once a second
    # one has been read.
    assert failure.release_id == release
    assert result.written == []


@pytest.mark.parametrize(
    "release",
    [
        pytest.param({"release_id": FULL_RELEASE}, id="a commit sha"),
        pytest.param({"release_id": ""}, id="empty"),
        pytest.param({"release_id": None}, id="null"),
        pytest.param({}, id="absent"),
    ],
)
def test_a_manifest_with_a_full_release_id_or_none_is_fetched(
    tmp_path: pathlib.Path, release: dict[str, Any]
) -> None:
    packs = two_packs()
    data, manifest = packs["aws-s3"]
    unpinned = {name: value for name, value in manifest.items() if name != "release_id"}
    packs["aws-s3"] = (data, {**unpinned, **release})

    result = fetch(PackClient(packs), release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    assert result.failed == {}
    assert len(result.written) == len(ENTRIES)


def test_an_unsafe_entry_fails_its_pack_at_extraction(tmp_path: pathlib.Path) -> None:
    packs = two_packs()
    data = archive_of({**ENTRIES, "../escape.rego": b"package x"})
    packs["aws-s3"] = (data, manifest_for(data, pack(ENTRIES)[1]["rules"]))

    result = fetch(PackClient(packs), out=tmp_path)  # type: ignore[arg-type]

    failure = result.failed["aws-s3"]
    assert (failure.stage, failure.code) == ("extract", "archive_unsafe")
    assert (tmp_path / "gcp-bigquery" / "Bigquery.C102" / "metadata.json").exists()
    assert not (tmp_path / "aws-s3").exists()


#: What the API says about a pack whose stored archive no longer matches the
#: digest it published, once the client has retried and given up.
DAMAGED = "The source archive of aws-s3 does not match its published digest."


def test_a_refused_archive_fails_only_its_pack(tmp_path: pathlib.Path) -> None:
    client = PackClient(two_packs())
    client.archive_errors["aws-s3"] = ServiceUnavailable(
        DAMAGED, code="unavailable", status=503, request_id="r-1"
    )

    result = fetch(client, out=tmp_path)  # type: ignore[arg-type]

    assert result.failed == {
        "aws-s3": PackFailure(
            release_key="aws-s3",
            stage="archive",
            code="unavailable",
            message=DAMAGED,
            status=503,
            request_id="r-1",
            release_id="d07d6aee",
        )
    }
    assert result.written == [
        tmp_path / "gcp-bigquery" / "Bigquery.C102" / "metadata.json"
    ]
    assert not (tmp_path / "aws-s3").exists()


def test_an_outage_reading_a_manifest_stops_the_fetch(tmp_path: pathlib.Path) -> None:
    # The API itself is struggling when it cannot serve a manifest, so every
    # later pack would most likely fail the same way.
    class Struggling(PackClient):
        def get(
            self, path: str, params: Mapping[str, str] | None = None
        ) -> dict[str, Any]:
            raise ServiceUnavailable("Try later.", code="unavailable", status=503)

    with pytest.raises(ServiceUnavailable):
        fetch(Struggling(two_packs()), out=tmp_path)  # type: ignore[arg-type]


def test_a_rate_limit_on_an_archive_stops_the_fetch(tmp_path: pathlib.Path) -> None:
    client = PackClient(two_packs())
    client.archive_errors["aws-s3"] = RateLimited(
        "Slow down.", retry_after=3600, code="rate_limited", status=429
    )

    with pytest.raises(RateLimited):
        fetch(client, out=tmp_path)  # type: ignore[arg-type]


def test_a_failure_without_a_code_is_named_by_its_class(
    tmp_path: pathlib.Path,
) -> None:
    # A bare 502 from whatever sits in front of the API carries no envelope,
    # so it has no code of its own.
    client = PackClient(two_packs())
    client.archive_errors["aws-s3"] = ServiceUnavailable(
        "The API answered 502.", status=502
    )

    result = fetch(client, release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    assert result.failed["aws-s3"].code == "ServiceUnavailable"


class AlwaysSuperseded(PackClient):
    """A client whose pack is republished before every archive read."""

    def get_bytes(self, path: str, params: Mapping[str, str] | None = None) -> bytes:
        self.calls.append((path, dict(params or {})))
        raise ReleaseSuperseded("Superseded.", code="release_superseded", status=410)


def test_a_release_that_changes_twice_in_a_row_fails_the_pack(
    tmp_path: pathlib.Path,
) -> None:
    client = AlwaysSuperseded(two_packs())

    result = fetch(client, release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    assert set(result.failed) == {"aws-s3"}
    failure = result.failed["aws-s3"]
    assert (failure.stage, failure.code) == ("archive", "release_superseded")
    # One retry and no more: the manifest is read twice, and the archive twice.
    assert [p for p, _ in client.calls].count("/v1/ccr/packs/aws-s3") == 2
    assert [p for p, _ in client.calls].count("/v1/ccr/packs/aws-s3/archive") == 2
    assert not (tmp_path / "aws-s3").exists()


def test_a_credential_failure_is_not_a_packs_failure() -> None:
    class Unauthorised(PackClient):
        def get(
            self, path: str, params: Mapping[str, str] | None = None
        ) -> dict[str, Any]:
            raise AuthenticationError("Bad key.", status=401)

    with pytest.raises(AuthenticationError):
        fetch(Unauthorised(two_packs()), release_keys=("aws-s3",))  # type: ignore[arg-type]


#: The hint for an archive the API refused, as people read it on stderr.
REFUSED_HINT = (
    "The API refused the archive after this client retried, and its message "
    "says why. A damaged archive stays refused until the pack is republished; "
    "for anything else, run the command again later. If it keeps failing, "
    "report the request id."
)

#: The hint for a pack the key cannot read.
UNKNOWN_HINT = (
    "The pack is unknown or not in this tenant's subscription; "
    "`tmxcaliber ccr packs list` shows the packs this key can read."
)


def test_a_pack_failure_reads_as_one_line() -> None:
    failure = PackFailure(
        release_key="aws-s3",
        stage="archive",
        code="unavailable",
        message=DAMAGED,
        status=503,
        request_id="r-1",
        release_id="d07d6aee0123",
    )

    assert str(failure) == (
        f"archive failed: {DAMAGED} [unavailable, HTTP 503, request r-1, "
        f"release d07d6ae]. {REFUSED_HINT}"
    )


def test_a_failed_pack_keeps_a_full_length_release_id_and_prints_seven(
    tmp_path: pathlib.Path,
) -> None:
    packs = two_packs()
    data, manifest = packs["aws-s3"]
    packs["aws-s3"] = (data, {**manifest, "release_id": FULL_RELEASE})
    client = PackClient(packs)
    client.archive_errors["aws-s3"] = ServiceUnavailable(
        DAMAGED, code="unavailable", status=503, request_id="r-1"
    )

    result = fetch(client, release_keys=("aws-s3",), out=tmp_path)  # type: ignore[arg-type]

    failure = result.failed["aws-s3"]
    # The field keeps the whole id for a script; the line people read is cut
    # to seven characters, as a short commit hash is.
    assert failure.release_id == FULL_RELEASE
    assert str(failure) == (
        f"archive failed: {DAMAGED} [unavailable, HTTP 503, request r-1, "
        f"release {FULL_RELEASE[:7]}]. {REFUSED_HINT}"
    )


def test_a_pack_failure_leaves_out_what_it_does_not_know() -> None:
    failure = PackFailure(
        release_key="aws-nothing",
        stage="manifest",
        code="not_found",
        message="No such pack.",
        status=404,
    )

    assert str(failure) == (
        f"manifest failed: No such pack. [not_found, HTTP 404]. {UNKNOWN_HINT}"
    )


def test_a_pack_failure_with_nothing_to_bracket_has_no_brackets() -> None:
    failure = PackFailure(
        release_key="aws-s3", stage="manifest", code="", message="Gone."
    )

    # The message already ends its sentence, so no second full stop follows.
    assert str(failure) == f"manifest failed: Gone. {failure.hint}"


@pytest.mark.parametrize(
    ("stage", "code", "expected"),
    [
        ("archive", "unavailable", REFUSED_HINT),
        ("manifest", "not_found", UNKNOWN_HINT),
        ("archive", "not_found", "withdrawn"),
        ("archive", "timeout", "could not be downloaded"),
        ("archive", "release_superseded", "republished while it was being read"),
        ("verify", "bad_manifest", "does not match its manifest"),
        ("extract", "archive_unwritable", "permissions and free space"),
        ("extract", "archive_unreadable", "report the release id"),
        ("manifest", "bad_body", "report the request id"),
    ],
)
def test_a_pack_failure_says_what_to_do(stage: str, code: str, expected: str) -> None:
    failure = PackFailure(release_key="aws-s3", stage=stage, code=code, message="x")

    assert expected in failure.hint

"""Select CCR rules from pack manifests, and write their files from a pack archive.

`ccr fetch`, for the CLI and for `Client` alike. The API serves a pack as two
things: its manifest, which names every rule and every file, and its source
archive, which holds those files. Selection runs on the manifest, so a pack
with nothing selected is never downloaded. Extraction runs on the archive, and
only after the archive has proved to be the one the manifest describes.

A rule's files are laid out ``<mode>/<matcher>/...`` under its control id, so
the mode and matcher filters narrow the files written as well as the rules
chosen.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Final

from .errors import ContractViolation

#: The modes a rule can ship, as ccr_factory names them.
MODES: Final[tuple[str, ...]] = ("universal", "allowlist", "denylist")

#: The matchers a rule can implement: live Wiz resources, and Terraform.
MATCHERS: Final[tuple[str, ...]] = ("cloud", "terraform")


@dataclass(frozen=True)
class RuleFilter:
    """What a caller asked for.

    Repeats of one field are alternatives and different fields must all hold,
    so ``modes=("allowlist",), matchers=("cloud",)`` is allowlist rules with a
    cloud matcher. An empty field does not narrow anything.

    Attributes:
        controls: Control ids, matched case-insensitively.
        modes: Modes a rule must ship one of.
        matchers: Matchers a rule must implement one of.
        files: Globs over ``<rule id>/<file>``; ``*`` also matches ``/``.
    """

    controls: tuple[str, ...] = ()
    modes: tuple[str, ...] = ()
    matchers: tuple[str, ...] = ()
    files: tuple[str, ...] = ()


@dataclass(frozen=True)
class Selected:
    """One chosen rule, and which of its files to write.

    Attributes:
        rule: The manifest's entry for the rule.
        files: The rule's selected files, relative to its folder.
    """

    rule: Mapping[str, Any]
    files: tuple[str, ...]


def _file_kept(rule_id: str, file: str, wanted: RuleFilter) -> bool:
    """Decide whether one of a rule's files is written.

    Args:
        rule_id: The rule's control id.
        file: The file, relative to the rule's folder.
        wanted: The filter.

    Returns:
        True when every filter that applies to the file lets it through.
    """
    parts = file.split("/")
    # A file at the rule's root, such as metadata.json, describes the rule as
    # a whole, so neither the mode nor the matcher filter removes it.
    if len(parts) > 1 and wanted.modes and parts[0] not in wanted.modes:
        return False
    # Only a file inside a matcher folder belongs to one matcher. A mode-level
    # file, such as allowlist/remediation.md, applies to both.
    if len(parts) > 2 and wanted.matchers and parts[1] not in wanted.matchers:
        return False
    return not wanted.files or any(
        fnmatchcase(f"{rule_id}/{file}", pattern) for pattern in wanted.files
    )


def select_rules(manifest: Mapping[str, Any], wanted: RuleFilter) -> list[Selected]:
    """Choose a pack's rules, and each rule's files, by the filter.

    Args:
        manifest: The pack's manifest, as ``ccr packs get`` returns it.
        wanted: The filter.

    Returns:
        The chosen rules, in manifest order.

    Raises:
        ContractViolation: If a rule entry is not an object.
    """
    controls = {control.lower() for control in wanted.controls}
    chosen: list[Selected] = []
    for rule in manifest.get("rules") or []:
        if not isinstance(rule, Mapping):
            raise ContractViolation(
                "A pack manifest lists a rule that is not an object.",
                code="bad_manifest",
            )
        rule_id = str(rule.get("id", ""))
        if controls and rule_id.lower() not in controls:
            continue
        if wanted.modes and not set(wanted.modes) & set(rule.get("modes") or []):
            continue
        matchers = rule.get("matchers") or {}
        if wanted.matchers and not any(
            (matchers.get(name) or {}).get("implemented") is True
            for name in wanted.matchers
        ):
            continue
        files = tuple(
            str(file)
            for file in rule.get("files") or []
            if _file_kept(rule_id, str(file), wanted)
        )
        if wanted.files and not files:
            continue
        chosen.append(Selected(rule=rule, files=files))
    return chosen


def rule_row(release_key: str, release_id: str, chosen: Selected) -> dict[str, Any]:
    """Render one chosen rule as the row ``ccr fetch`` prints.

    Args:
        release_key: The pack.
        release_id: The release the manifest came from.
        chosen: The rule.

    Returns:
        The row, in the API's camelCase.
    """
    rule = chosen.rule
    return {
        "releaseKey": release_key,
        "releaseId": release_id,
        "ruleId": str(rule.get("id", "")),
        "name": rule.get("name", ""),
        "modes": list(rule.get("modes") or []),
        "matchers": rule.get("matchers") or {},
        "weightedPriority": rule.get("weighted_priority", ""),
        "files": list(chosen.files),
    }


def verify_archive(data: bytes, manifest: Mapping[str, Any], release_key: str) -> None:
    """Refuse an archive that is not the one its manifest describes.

    The API checks the same digest before serving, so a mismatch here means
    the bytes changed in transit or the manifest came from another release.
    Either way nothing from the archive is written.

    Args:
        data: The archive.
        manifest: The manifest the rules were selected from.
        release_key: The pack, for the message.

    Raises:
        ContractViolation: If the manifest describes no source archive, or the
            archive's size or digest differs from it.
    """
    block = manifest.get("bundle")
    if not isinstance(block, Mapping) or not block.get("sha256"):
        raise ContractViolation(
            f"{release_key}'s manifest describes no source archive.",
            code="bad_manifest",
        )
    size = block.get("bytes")
    if isinstance(size, int) and size != len(data):
        raise ContractViolation(
            f"{release_key}'s archive is {len(data)} bytes; its manifest says {size}.",
            code="archive_mismatch",
        )
    if hashlib.sha256(data).hexdigest() != block["sha256"]:
        raise ContractViolation(
            f"{release_key}'s archive does not match its manifest's digest.",
            code="archive_mismatch",
        )


def _is_safe(name: str) -> bool:
    """Decide whether an archive entry name stays inside its pack folder.

    Args:
        name: The entry name.

    Returns:
        False for an absolute name, a backslash, a drive or other colon, or an
        empty, ``.`` or ``..`` segment.
    """
    if not name or name.startswith("/") or "\\" in name or ":" in name:
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


def extract(
    data: bytes,
    manifest: Mapping[str, Any],
    release_key: str,
    chosen: Sequence[Selected],
    out: Path,
) -> list[Path]:
    """Write the selected files of a verified archive under ``out/<release_key>``.

    **All or nothing per pack.** Every check runs, and every file is written to
    a staging folder inside ``out``, before anything reaches its final place,
    so a refused pack leaves ``out`` as it was.

    Args:
        data: The archive, already verified with `verify_archive`.
        manifest: The manifest the rules were selected from.
        release_key: The pack.
        chosen: The rules and files to write.
        out: The folder to write under.

    Returns:
        Every file written, in selection order.

    Raises:
        ContractViolation: If any entry is unsafe or undeclared, or a selected
            file is missing from the archive.
    """
    declared = {
        f"{rule.get('id')}/{file}"
        for rule in manifest.get("rules") or []
        if isinstance(rule, Mapping)
        for file in rule.get("files") or []
    }
    wanted = [f"{s.rule.get('id')}/{file}" for s in chosen for file in s.files]
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = {name for name in archive.namelist() if not name.endswith("/")}
        unsafe = sorted(name for name in entries if not _is_safe(name))
        if unsafe:
            raise ContractViolation(
                f"{release_key}'s archive holds an unsafe entry: {unsafe[0]!r}.",
                code="archive_unsafe",
            )
        undeclared = sorted(entries - declared)
        if undeclared:
            raise ContractViolation(
                f"{release_key}'s archive holds {undeclared[0]}, which its manifest "
                "does not declare.",
                code="archive_mismatch",
            )
        missing = [name for name in wanted if name not in entries]
        if missing:
            raise ContractViolation(
                f"{release_key}'s archive lacks {missing[0]}, which its manifest "
                "declares.",
                code="archive_mismatch",
            )
        out.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{release_key}-", dir=out))
        try:
            for name in wanted:
                staged = staging.joinpath(*name.split("/"))
                staged.parent.mkdir(parents=True, exist_ok=True)
                staged.write_bytes(archive.read(name))
            written: list[Path] = []
            for name in wanted:
                final = out.joinpath(release_key, *name.split("/"))
                final.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staging.joinpath(*name.split("/")), final)
                written.append(final)
            return written
        finally:
            shutil.rmtree(staging, ignore_errors=True)

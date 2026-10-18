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

import contextlib
import hashlib
import io
import lzma
import os
import re
import stat
import tempfile
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Final

from .client import TocClient
from .contract import Route, route_for
from .errors import (
    ContractViolation,
    NotFound,
    ReleaseSuperseded,
    RemoteError,
    ServiceUnavailable,
)
from .operations import call_route

#: The modes a rule can ship, as ccr_factory names them.
MODES: Final[tuple[str, ...]] = ("universal", "allowlist", "denylist")

#: The matchers a rule can implement: live Wiz resources, and Terraform.
MATCHERS: Final[tuple[str, ...]] = ("cloud", "terraform")

#: The steps of fetching one pack, in the order they run, as `PackFailure`
#: names them: reading the manifest and selecting from it, downloading the
#: archive, checking the archive against the manifest, and writing its files.
STAGES: Final[tuple[str, ...]] = ("manifest", "archive", "verify", "extract")


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


#: The filter that selects everything, which is `fetch`'s default. It is a
#: module-level value because a call in a default argument is refused by the
#: linter (B008). Callers share this one instance, which is safe because
#: `RuleFilter` is frozen.
_NO_FILTER: Final[RuleFilter] = RuleFilter()


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


#: What reading a damaged or unsupported archive from memory can raise. Each one
#: is a verdict on the bytes, because nothing here touches the disk:
#: ``RuntimeError`` covers an encrypted entry and, through its subclass
#: ``NotImplementedError``, a compression method zipfile cannot decode,
#: ``OSError`` is how the bzip2 decoder reports a corrupt stream, and
#: ``ValueError`` covers a header that points before the start of the archive
#: (``negative seek value``) and, through its subclass ``UnicodeDecodeError``, an
#: entry name flagged as UTF-8 that is not valid UTF-8.
_UNREADABLE: Final[tuple[type[Exception], ...]] = (
    zipfile.BadZipFile,
    EOFError,
    RuntimeError,
    OSError,
    ValueError,
    zlib.error,
    lzma.LZMAError,
)

#: Characters Windows refuses in a file name. The colon is left out because
#: `_is_safe` already refuses it.
_WINDOWS_INVALID: Final[frozenset[str]] = frozenset('<>"|?*')

#: Names Windows reserves for devices, whatever extension follows them.
_WINDOWS_DEVICES: Final[frozenset[str]] = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{n}" for n in range(1, 10)}
    | {f"lpt{n}" for n in range(1, 10)}
)

#: The form of a pack's release key, which is the API's own rule
#: (``isSafeReleaseKey``): lowercase letters and digits in two or more groups
#: joined by single hyphens, as in ``aws-s3``. The key becomes a folder name
#: under the output folder and the API never sends one that does not fit, so
#: this client accepts exactly that form instead of listing what could go wrong
#: in a folder name. It is matched with ``fullmatch`` because ``$`` also accepts
#: a trailing newline.
_RELEASE_KEY: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")


def _is_safe(name: str) -> bool:
    """Decide whether an archive entry name stays inside its pack folder.

    Args:
        name: The entry name as the archive stores it. A name as zipfile reports
            it is no use here on Windows, where it has already lost its
            backslashes.

    Returns:
        False for an absolute name, a backslash, a drive or other colon, or an
        empty, ``.`` or ``..`` segment.
    """
    if not name or name.startswith("/") or "\\" in name or ":" in name:
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


def _is_portable(name: str) -> bool:
    """Decide whether a file can be written on Windows as well as elsewhere.

    A pack is built on Linux, where ``what?.md`` and ``x.rego.`` are ordinary
    names. The same selection has to lay out the same way on every machine that
    fetches it, and Windows either refuses such a name or quietly writes a
    different one, so the check holds on every platform.

    Args:
        name: A path relative to the pack folder, with ``/`` separators.

    Returns:
        False when a segment holds a character Windows forbids or a control
        character, ends in a dot or a space, or is a reserved device name such
        as ``nul`` or ``con.txt``. The ``.`` and ``..`` segments are left to
        `_is_safe`.
    """
    for part in name.split("/"):
        if part in (".", ".."):
            continue
        if any(char in _WINDOWS_INVALID or ord(char) < 32 for char in part):
            return False
        if part.endswith((".", " ")):
            return False
        if part.split(".", 1)[0].rstrip(" ").casefold() in _WINDOWS_DEVICES:
            return False
    return True


def _refuse_unsafe_key(release_key: str) -> None:
    """Refuse a release key that is not the form the API issues.

    The key is joined onto ``out`` as a folder name, and it reaches this client
    from an API response, so a key such as ``..`` or ``a/b`` would send every
    file of the pack outside ``out``. The checks on the manifest's paths and on
    the archive's names cannot see it, because the key is not part of either.
    A null byte in a key would also end a fetch with a raw ``ValueError`` from
    the disk calls.

    Args:
        release_key: The pack.

    Raises:
        ContractViolation: If the key does not match the API's own form (code
            ``archive_unsafe``).
    """
    if not _RELEASE_KEY.fullmatch(release_key):
        raise ContractViolation(
            f"The pack key {release_key!r} is not in the form the API issues, so "
            "nothing is written under it.",
            code="archive_unsafe",
        )


def _refuse_unwritable(wanted: Sequence[str], release_key: str) -> None:
    """Refuse a selection that cannot be laid out as separate files.

    Run before anything is written, so a refused pack leaves ``out`` as it was.
    Without it a repeated path would be staged once per mention and then moved
    only once, and two names that land on one path would overwrite each other
    or fail part way through the moves.

    The selected paths are the strings that are joined onto ``out``, so they are
    judged here for leaving their folder, whatever the archive's names say. An
    archive can report an entry under another name than the one it stores, and
    a check on the stored names cannot vouch for what reaches the disk then.

    Args:
        wanted: The selected paths, each ``<rule id>/<file>``.
        release_key: The pack, for the message.

    Raises:
        ContractViolation: If the manifest lists a path twice (code
            ``bad_manifest``), or a path could leave its folder, is one Windows
            cannot write, equals another once case is ignored, or is both a
            file and a folder of another (code ``archive_unsafe``).
    """
    seen: set[str] = set()
    for name in wanted:
        if name in seen:
            raise ContractViolation(
                f"{release_key}'s manifest lists {name} more than once.",
                code="bad_manifest",
            )
        seen.add(name)
    by_folded: dict[str, str] = {}
    for name in wanted:
        if not _is_safe(name):
            raise ContractViolation(
                f"{release_key}'s manifest declares {name!r}, which could leave "
                "its folder.",
                code="archive_unsafe",
            )
        if not _is_portable(name):
            raise ContractViolation(
                f"{release_key}'s manifest declares {name!r}, which cannot be "
                "written as a file on Windows.",
                code="archive_unsafe",
            )
        other = by_folded.setdefault(name.casefold(), name)
        if other != name:
            raise ContractViolation(
                f"{release_key}'s manifest declares {other} and {name}, which are "
                "one file wherever case does not matter.",
                code="archive_unsafe",
            )
    for folded, name in by_folded.items():
        parts = folded.split("/")
        for depth in range(1, len(parts)):
            parent = by_folded.get("/".join(parts[:depth]))
            if parent is not None:
                raise ContractViolation(
                    f"{release_key}'s manifest declares {parent} as a file and "
                    f"{name} inside it as a folder.",
                    code="archive_unsafe",
                )


def _refuse_folders_in_the_way(
    wanted: Sequence[str], release_key: str, out: Path
) -> None:
    """Refuse a selection when a folder sits where one of its files belongs.

    A file already at its final path is set aside and put back if the pack
    fails, and is dropped once the pack succeeds. That is right for the file an
    earlier fetch wrote, and wrong for a folder, which holds whatever else
    someone keeps there and would go with it. Nothing this client writes is a
    folder at a file's path, so the folder is not ours to replace.

    Args:
        wanted: The paths to write, each ``<rule id>/<file>``.
        release_key: The pack.
        out: The folder to write under.

    Raises:
        ContractViolation: If a folder, or a link to one, is at a final path, or
            a final path cannot be examined, such as one inside a folder this
            user cannot search (code ``archive_unwritable``). The disk's error
            is the cause in the second case. Python 3.10 to 3.12 raise it from
            ``Path.is_dir``, and without this it would end a whole fetch.
    """
    for name in wanted:
        final = out.joinpath(release_key, *name.split("/"))
        try:
            in_the_way = final.is_dir()
        except OSError as exc:
            raise ContractViolation(
                f"{release_key}'s file {name} cannot be written, because {final} "
                f"cannot be examined: {exc} Nothing was changed.",
                code="archive_unwritable",
            ) from exc
        if in_the_way:
            raise ContractViolation(
                f"{release_key}'s file {name} cannot be written, because {final} "
                "is a folder.",
                code="archive_unwritable",
            )


def _read_member(archive: zipfile.ZipFile, name: str, release_key: str) -> bytes:
    """Read one entry, naming the pack when the archive cannot give it up.

    Args:
        archive: The open archive.
        name: The entry.
        release_key: The pack, for the message.

    Returns:
        The entry's content.

    Raises:
        ContractViolation: If the entry is damaged, encrypted, or compressed
            with a method this client cannot decode.
    """
    try:
        return archive.read(name)
    except _UNREADABLE as exc:
        raise ContractViolation(
            f"{release_key}'s archive cannot give up {name}: {exc}",
            code="archive_unreadable",
        ) from exc


def _make_folder(folder: Path, created: list[Path]) -> None:
    """Create a folder, and record each level this call had to create.

    Args:
        folder: The folder to create, with any parents it needs.
        created: Receives each level that did not exist, outermost first, so a
            failure can remove exactly what this call added.
    """
    missing = [level for level in (folder, *folder.parents) if not level.exists()]
    for level in reversed(missing):
        try:
            level.mkdir()
        except FileExistsError:
            # Another process made it first, so this call must leave it alone.
            continue
        created.append(level)


def _put_back(placed: Sequence[tuple[Path, Path | None]]) -> bool:
    """Undo moves into place, newest first.

    Args:
        placed: Each final path that was moved to, and where the file that was
            already there went, or None when the path was free.

    Returns:
        True when every file that had been replaced is back where it was. This
        is best effort, because it runs while another failure is propagating.
    """
    restored = True
    for final, displaced in reversed(placed):
        with contextlib.suppress(OSError):
            final.unlink(missing_ok=True)
        if displaced is not None:
            try:
                os.replace(displaced, final)
            except OSError:
                restored = False
    return restored


def _remove_tree(folder: Path) -> None:
    """Delete a folder and everything in it, read-only files included.

    ``shutil.rmtree`` cannot delete a read-only file on Windows. The staging
    folder holds the old copy of every file a pack replaced, and an earlier
    fetch may have left that copy read-only, so with ``rmtree`` a hidden folder
    of stale files would stay in the output folder after a pack that succeeded.
    The attribute is cleared only when a delete is refused. This is best effort,
    because it also runs while another failure is propagating, and an error from
    it would take the place of that failure. Whatever cannot be deleted stays
    behind, hidden, and the pack's own outcome is reported as it was.

    Args:
        folder: The folder to delete.
    """
    for parent, _, files in os.walk(folder, topdown=False):
        for name in files:
            path = os.path.join(parent, name)
            try:
                os.unlink(path)
            except OSError:
                with contextlib.suppress(OSError):
                    os.chmod(path, stat.S_IWRITE)
                    os.unlink(path)
        with contextlib.suppress(OSError):
            os.rmdir(parent)


def _install(
    archive: zipfile.ZipFile,
    wanted: Sequence[str],
    release_key: str,
    out: Path,
    created: list[Path],
) -> list[Path]:
    """Stage the selected files, then move them into ``out/<release_key>``.

    A file already at its final path is set aside inside the staging folder
    first. If any step then fails, the files already moved are taken out again
    and the ones they replaced are put back, so a failed pack never leaves a mix
    of old and new files. When even that cannot be done, the staging folder is
    kept, because it holds the only copy of what could not be put back.

    Args:
        archive: The open archive.
        wanted: The paths to write, each ``<rule id>/<file>``.
        release_key: The pack.
        out: The folder to write under.
        created: Receives each folder this call makes, outermost first.

    Returns:
        Every file written, in the order of ``wanted``.

    Raises:
        ContractViolation: If an entry cannot be read, or the disk refuses to
            make ``out`` or the staging folder, or refuses a write or a move
            (code ``archive_unwritable``). The disk's error is the cause. It is
            reported as a failed pack, as an unreadable entry is, because
            ``fetch`` has to be able to go on to the next pack when one file is
            held open by another program, and has to report a folder the user
            cannot write as a failed pack instead of a traceback.
    """
    placed: list[tuple[Path, Path | None]] = []
    keep_staging = False
    staging: Path | None = None
    try:
        _make_folder(out, created)
        staging = Path(tempfile.mkdtemp(prefix=f".{release_key}-", dir=out))
        for name in wanted:
            staged = staging.joinpath("new", *name.split("/"))
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(_read_member(archive, name, release_key))
        written: list[Path] = []
        for index, name in enumerate(wanted):
            final = out.joinpath(release_key, *name.split("/"))
            _make_folder(final.parent, created)
            displaced: Path | None = None
            if os.path.lexists(final):
                displaced = staging / "old" / str(index)
                displaced.parent.mkdir(exist_ok=True)
                os.replace(final, displaced)
            placed.append((final, displaced))
            os.replace(staging.joinpath("new", *name.split("/")), final)
            written.append(final)
        return written
    except OSError as exc:
        # When the failure came before the staging folder existed, nothing has
        # been placed, so there is nothing to put back and nothing to keep.
        restored = _put_back(placed)
        keep_staging = not restored
        outcome = (
            "Nothing was changed."
            if restored
            else f"Files it replaced could not be put back, and are kept in {staging}."
        )
        raise ContractViolation(
            f"{release_key}'s files could not be written under {out}: {exc} {outcome}",
            code="archive_unwritable",
        ) from exc
    except BaseException:
        keep_staging = not _put_back(placed)
        raise
    finally:
        if staging is not None and not keep_staging:
            _remove_tree(staging)


def extract(
    data: bytes,
    manifest: Mapping[str, Any],
    release_key: str,
    chosen: Sequence[Selected],
    out: Path,
) -> list[Path]:
    """Write the selected files of a verified archive under ``out/<release_key>``.

    **All or nothing per pack.** Every check runs, and every selected file is
    read and written to a staging folder inside ``out``, before anything
    reaches its final place, so a refused pack leaves ``out`` as it was. If a
    move into place then fails, the files already moved are taken back out, any
    file they replaced is restored, and the folders this call made are removed,
    so that failure leaves ``out`` as it was too.

    Args:
        data: The archive, already verified with `verify_archive`.
        manifest: The manifest the rules were selected from.
        release_key: The pack.
        chosen: The rules and files to write.
        out: The folder to write under.

    Returns:
        Every file written, in selection order.

    Raises:
        ContractViolation: If the archive cannot be read (code
            ``archive_unreadable``), any entry is unsafe or undeclared, an entry
            reads under another name than the one it stores, a selected file is
            missing from the archive, or the selection lists a path twice,
            holds one that could leave its folder, or names files that cannot
            sit side by side on every platform. Also, with code
            ``archive_unsafe``, if the pack's key is not in the form the API
            issues, because a key such as ``..`` would name a folder outside
            ``out``. Also, with code ``archive_unwritable``, if a folder is
            where a file belongs, a path under ``out`` cannot be examined, or
            the disk refuses to make ``out`` or to write or move a file, in
            which case ``out`` has been put back as it was.
    """
    declared = {
        f"{rule.get('id')}/{file}"
        for rule in manifest.get("rules") or []
        if isinstance(rule, Mapping)
        for file in rule.get("files") or []
    }
    wanted = [f"{s.rule.get('id')}/{file}" for s in chosen for file in s.files]
    # The key and these paths are what gets joined onto ``out``, so they are
    # judged before the archive is looked at. Nothing the archive's names say
    # can vouch for them.
    _refuse_unsafe_key(release_key)
    _refuse_unwritable(wanted, release_key)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except _UNREADABLE as exc:
        raise ContractViolation(
            f"{release_key}'s archive is not a readable zip: {exc}",
            code="archive_unreadable",
        ) from exc
    with archive:
        # The name is judged as stored, because on Windows zipfile has already
        # turned every backslash in the name it reports into a slash, which
        # would let an entry through there that Linux refuses. The name zipfile
        # reports is still the one to compare with the manifest and to read by.
        stored = [
            info for info in archive.infolist() if not info.orig_filename.endswith("/")
        ]
        entries = {info.filename for info in stored}
        unsafe = sorted(
            info.orig_filename for info in stored if not _is_safe(info.orig_filename)
        )
        if unsafe:
            raise ContractViolation(
                f"{release_key}'s archive holds an unsafe entry: {unsafe[0]!r}.",
                code="archive_unsafe",
            )
        # zipfile reports a name that an extra field gives an entry, and a name
        # cut at its first null byte, in place of the stored one. Only the
        # reported name is read and compared, so the check on the stored name
        # above would say nothing about it. Backslashes are set aside here
        # because zipfile folds them on Windows only, and the check above has
        # already refused them in every entry that is written.
        renamed = sorted(
            info.orig_filename
            for info in archive.infolist()
            if info.filename.replace("\\", "/") != info.orig_filename.replace("\\", "/")
        )
        if renamed:
            raise ContractViolation(
                f"{release_key}'s archive holds an entry stored as {renamed[0]!r} "
                "that reads as another name.",
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
        _refuse_folders_in_the_way(wanted, release_key, out)
        created: list[Path] = []
        try:
            return _install(archive, wanted, release_key, out, created)
        except BaseException:
            # Whatever the install put in these folders is gone by now, so the
            # ones left are empty and removing them restores ``out``.
            for folder in reversed(created):
                with contextlib.suppress(OSError):
                    folder.rmdir()
            raise


def _route(command: tuple[str, ...]) -> Route:
    """Find a CCR route by its command.

    Args:
        command: The command words.

    Returns:
        The route.
    """
    found = route_for(command)
    assert found is not None, f"{' '.join(command)} is not bound"
    return found


#: Archive-stage codes for a download the transport gave up on, as `TocClient`
#: names them. There is no server message or request id to go on then.
_LOST: Final[tuple[str, ...]] = ("unreachable", "timeout", "connection_lost")

#: What to do about a failed pack, by its stage and code. A code of None stands
#: for every code of that stage without a line of its own.
_HINTS: Final[Mapping[tuple[str, str | None], str]] = {
    ("manifest", "not_found"): (
        "The pack is unknown or not in this tenant's subscription; "
        "`tmxcaliber ccr packs list` shows the packs this key can read."
    ),
    ("archive", "not_found"): (
        "The pack was withdrawn, or left this tenant's subscription, after its "
        "manifest was read; `tmxcaliber ccr packs list` shows the packs this key "
        "can read."
    ),
    ("archive", "unavailable"): (
        "The API refused the archive after this client retried, for the reason in "
        "the message; run the command again later, and if it keeps failing, report "
        "the request id."
    ),
    **{
        ("archive", code): (
            "The archive could not be downloaded after this client retried; check "
            "the connection and run the command again."
        )
        for code in _LOST
    },
    ("archive", "release_superseded"): (
        "The pack was republished while it was being read; run the command again."
    ),
    ("verify", None): (
        "The downloaded archive does not match its manifest, so nothing from this "
        "pack was written; run the command again, and if it persists, report the "
        "request id or the release."
    ),
    ("extract", "archive_unwritable"): (
        "A file could not be written under the output folder; check its "
        "permissions and free space."
    ),
    ("extract", None): (
        "The archive holds entries this client refuses to write, so nothing from "
        "this pack was written; report the release id."
    ),
}

#: What to do about a failure no line of `_HINTS` covers.
_GENERAL_HINT: Final[str] = (
    "The message says what went wrong; if it persists, report the request id."
)


@dataclass(frozen=True)
class PackFailure:
    """One pack that could not be fetched, and why.

    A damaged archive and an outage both reach this client as a 503, so the
    stage, the code and the server's own message are what tell them apart,
    and the request id is what support will ask for. Each is a field of its
    own, so a script can branch on it without parsing the line people read.

    Attributes:
        release_key: The pack.
        stage: The step that failed, one of `STAGES`.
        code: The API's error code, such as ``unavailable``, or this client's
            own, such as ``archive_mismatch``. Never empty: an error that
            carries no code is named by its class instead.
        message: The server's words for an API error, or this client's for a
            local one, without the request id that the error's text appends.
        status: The HTTP status, when the failure reached one.
        request_id: The server's identifier for the request, when it sent one.
        release_id: The release the manifest named, when the manifest was read.
    """

    release_key: str
    stage: str
    code: str
    message: str
    status: int | None = None
    request_id: str | None = None
    release_id: str | None = None

    @property
    def hint(self) -> str:
        """Say, in one sentence, what to do about the failure.

        Returns:
            The sentence for this stage and code, else the one for this stage
            whatever the code, else a general one.
        """
        return (
            _HINTS.get((self.stage, self.code))
            or _HINTS.get((self.stage, None))
            or _GENERAL_HINT
        )

    def __str__(self) -> str:
        """Render the failure as the line ``ccr fetch`` prints for it.

        Returns:
            ``<stage> failed: <message> [<code>, HTTP <status>, request <id>,
            release <id>]. <hint>``, leaving out each detail that is not known,
            and the brackets when none is. The release id is cut to seven
            characters, which tell releases apart as a short commit hash does.
        """
        details = [
            detail
            for detail in (
                self.code,
                f"HTTP {self.status}" if self.status is not None else "",
                f"request {self.request_id}" if self.request_id else "",
                f"release {self.release_id[:7]}" if self.release_id else "",
            )
            if detail
        ]
        if details:
            return (
                f"{self.stage} failed: {self.message} [{', '.join(details)}]. "
                f"{self.hint}"
            )
        # The message is a sentence of its own, so a second full stop after it
        # would read as a typing slip.
        stop = "" if self.message.endswith((".", "!", "?")) else "."
        return f"{self.stage} failed: {self.message}{stop} {self.hint}"


@dataclass
class FetchResult:
    """What a fetch found and wrote.

    Attributes:
        rows: One row per selected rule, across every pack that completed.
        written: Every file written, when a folder was given.
        failed: Each pack that could not be fetched, by release key, with the
            stage it reached and why.
    """

    rows: list[dict[str, Any]] = field(default_factory=list)
    written: list[Path] = field(default_factory=list)
    failed: dict[str, PackFailure] = field(default_factory=dict)


def _pack_keys(
    client: TocClient,
    release_keys: Sequence[str],
    providers: Sequence[str],
    services: Sequence[str],
) -> list[str]:
    """Decide which packs to read.

    Args:
        client: The client.
        release_keys: Packs named by the caller.
        providers: Providers to narrow the listed packs to.
        services: Services to narrow the listed packs to.

    Returns:
        The release keys, in the order they will be read.
    """
    if release_keys:
        return list(dict.fromkeys(release_keys))
    keys: list[str] = []
    for row in call_route(client, _route(("ccr", "packs", "list")), "", {}).result:
        key = str(row.get("releaseKey") or "")
        # A release key is `<provider>-<service>`, split on its first hyphen,
        # as the API splits it to check entitlement.
        provider, _, service = key.partition("-")
        if providers and provider not in providers:
            continue
        if services and service not in services:
            continue
        keys.append(key)
    return keys


#: The errors that end only the pack they arise in, by the stage they arise at.
#: Anything else stops the whole fetch, because it would fail every later pack
#: the same way: a credential or permission failure, a rate limit, or an outage
#: that reaches the pack list or a manifest. An outage on the archive alone
#: belongs to its pack, because the API also answers 503 for an archive it will
#: not serve, such as one that no longer matches its published digest, while it
#: still serves every other pack. `TocClient` has retried it by then.
_PACK_ERRORS: Final[Mapping[str, tuple[type[RemoteError], ...]]] = {
    "manifest": (NotFound, ContractViolation),
    "archive": (NotFound, ReleaseSuperseded, ServiceUnavailable, ContractViolation),
    "verify": (ContractViolation,),
    "extract": (ContractViolation,),
}


def _failure(
    release_key: str, stage: str, exc: RemoteError, release_id: str
) -> PackFailure:
    """Describe the error that ended one pack.

    Args:
        release_key: The pack.
        stage: The step that failed, one of `STAGES`.
        exc: The error.
        release_id: The release the manifest named, or empty when no manifest
            was read.

    Returns:
        The failure.
    """
    return PackFailure(
        release_key=release_key,
        stage=stage,
        # A bare status from whatever sits in front of the API arrives without
        # a code, and an empty code would tell a script nothing.
        code=exc.code or type(exc).__name__,
        # `RemoteError.__str__` appends the request id, which has a field of
        # its own here, so the message is taken without it.
        message=Exception.__str__(exc),
        status=exc.status,
        request_id=exc.request_id,
        release_id=release_id or None,
    )


def _fetch_pack(
    client: TocClient, key: str, wanted: RuleFilter, out: Path | None
) -> tuple[list[dict[str, Any]], list[Path]] | PackFailure:
    """Select from one pack, and write its files when a folder is given.

    **One release throughout.** The archive is asked for the release the
    manifest names, so the files written are the ones the rules were chosen
    from. A pack republished between the two reads answers 410, and its
    manifest is read once more.

    **Each failure names its stage.** The stage decides whether an error ends
    this pack or the whole fetch (`_PACK_ERRORS`), and it tells the reader of a
    failed pack where to look.

    Args:
        client: The client.
        key: The pack.
        wanted: The filter.
        out: The folder to write under, or None to write nothing.

    Returns:
        The pack's rows and the files written, or what ended the pack when the
        error belongs to it alone: an unknown or unentitled pack, a release
        that changed twice in a row, an archive the API kept refusing, or one
        that is not what its manifest describes or cannot be written.

    Raises:
        RemoteError: On any other failure, which would end every later pack too.
    """
    stage = "manifest"
    release_id = ""
    try:
        for attempt in (1, 2):
            # A second manifest names a release of its own, so the first one's
            # id no longer describes the pack until it has been read.
            stage, release_id = "manifest", ""
            manifest = call_route(
                client, _route(("ccr", "packs", "get")), key, {}
            ).result
            release_id = str(manifest.get("release_id") or "")
            chosen = select_rules(manifest, wanted)
            rows = [rule_row(key, release_id, selected) for selected in chosen]
            if out is None or not chosen:
                return rows, []
            stage = "archive"
            try:
                data = call_route(
                    client,
                    _route(("ccr", "packs", "archive")),
                    key,
                    {"kind": "source", "release": release_id},
                ).result
            except ReleaseSuperseded:
                if attempt == 2:
                    raise
                continue
            stage = "verify"
            verify_archive(data, manifest, key)
            stage = "extract"
            return rows, extract(data, manifest, key, chosen, out)
    except RemoteError as exc:
        if not isinstance(exc, _PACK_ERRORS[stage]):
            raise
        return _failure(key, stage, exc, release_id)
    raise AssertionError("unreachable: the loop returns or raises")


def fetch(
    client: TocClient,
    *,
    release_keys: Sequence[str] = (),
    providers: Sequence[str] = (),
    services: Sequence[str] = (),
    wanted: RuleFilter = _NO_FILTER,
    out: Path | None = None,
) -> FetchResult:
    """Select CCR rules across packs, and write their files when asked.

    A pack that cannot be fetched is recorded in ``failed``, with the stage it
    reached, and the others still complete. That covers a pack that is unknown
    or not entitled, a release that changes twice during the read, an archive
    the API still refuses once the client has retried, and an archive that is
    not what its manifest describes or cannot be written. A failure that would
    end every pack the same way propagates instead: a credential, permission
    or rate limit failure, and an outage that reaches the pack list or a
    manifest.

    Args:
        client: The client.
        release_keys: Packs to read. Every entitled pack when empty.
        providers: Narrow the listed packs to these providers.
        services: Narrow the listed packs to these services.
        wanted: Which rules and files to select.
        out: The folder to write under, or None to only list.

    Returns:
        The rows, the files written and the packs that failed.

    Raises:
        ValueError: If packs are named and also narrowed by provider or service.
        RemoteError: On a failure that is not one pack's alone.
    """
    if release_keys and (providers or services):
        raise ValueError("Name packs, or narrow by provider and service, not both.")
    result = FetchResult()
    for key in _pack_keys(client, release_keys, providers, services):
        outcome = _fetch_pack(client, key, wanted, out)
        if isinstance(outcome, PackFailure):
            result.failed[key] = outcome
            continue
        rows, written = outcome
        result.rows.extend(rows)
        result.written.extend(written)
    return result

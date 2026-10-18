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

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
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

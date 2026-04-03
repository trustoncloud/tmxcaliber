from __future__ import annotations

from typing import Iterable

from .filter import Filter
from .threatmodel_data import ThreatModelData
from .tools import sort_by_id


def _get_controls_dict(tm: ThreatModelData) -> dict:
    data = tm.get_json().get("controls", {})
    return data if isinstance(data, dict) else {}


def _get_scorecard_dict(tm: ThreatModelData) -> dict:
    data = tm.get_json().get("scorecard", {})
    return data if isinstance(data, dict) else {}


def _canonical_id_map_from_iter(ids: Iterable[str]) -> dict[str, str]:
    """
    Build a lower->canonical mapping, first-seen casing wins.
    """
    out: dict[str, str] = {}
    for id_ in ids:
        if not isinstance(id_, str):
            continue
        lower = id_.lower()
        if lower and lower not in out:
            out[lower] = id_
    return out


def get_all_control_ids(models: list[ThreatModelData]) -> dict[str, str]:
    """
    Union of all control IDs present in controls across models.
    Returns lower->canonical mapping (canonical casing from JSON).
    """
    out: dict[str, str] = {}
    for tm in models:
        for control_id in _get_controls_dict(tm).keys():
            lower = control_id.lower()
            if lower and lower not in out:
                out[lower] = control_id
    return out


def get_aws_data_perimeter_control_ids(models: list[ThreatModelData]) -> dict[str, str]:
    """
    Union of all control IDs referenced by scorecard.aws_data_perimeter across models,
    excluding categories named "NA" (case-insensitive, stripped).
    Returns lower->canonical mapping (canonical casing as seen in scorecards).
    """
    out: dict[str, str] = {}
    for tm in models:
        scorecard = _get_scorecard_dict(tm)
        aws_data_perimeter = scorecard.get("aws_data_perimeter") or {}
        if not isinstance(aws_data_perimeter, dict):
            continue

        for category, ids in aws_data_perimeter.items():
            if isinstance(category, str) and category.strip().lower() == "na":
                continue
            if not isinstance(ids, list):
                continue
            for control_id in ids:
                if not isinstance(control_id, str):
                    continue
                lower = control_id.lower()
                if lower and lower not in out:
                    out[lower] = control_id
    return out


def expand_ids_to_control_ids_lower(
    models: list[ThreatModelData], filter_obj: Filter
) -> set[str]:
    """
    Expand Filter ids to a lowercased set of control IDs:
    1) direct control IDs (filter_obj.controls)
    2) any controls whose objective matches a provided control objective id
       (filter_obj.control_objectives), union across models.
    """
    requested: set[str] = set(x.lower() for x in (filter_obj.controls or []))

    requested_co: set[str] = set(
        x.lower() for x in (filter_obj.control_objectives or [])
    )
    if not requested_co:
        return requested

    for tm in models:
        for control_id, control_data in _get_controls_dict(tm).items():
            if not isinstance(control_data, dict):
                continue

            objective = control_data.get("objective")

            if isinstance(objective, str):
                if objective.strip().lower() in requested_co:
                    requested.add(control_id.lower())
            elif isinstance(objective, list):
                for obj in objective:
                    if isinstance(obj, str) and obj.strip().lower() in requested_co:
                        requested.add(control_id.lower())
                        break

    return requested


def resolve_control_ids(
    models: list[ThreatModelData],
    *,
    list_type: str,
    filter_obj: Filter,
    exclude: bool,
    ids_were_provided: bool,
) -> list[str]:
    """
    Resolve the final list of control IDs (canonical casing from JSON/scorecards)
    according to the agreed semantics.

    list_type:
    1) "ALL"
    2) "AWS_DATA_PERIMETER"

    Returns a sorted list using the project's sort_by_id() helper.
    """
    all_map = get_all_control_ids(models)

    if list_type == "AWS_DATA_PERIMETER":
        perimeter_map = get_aws_data_perimeter_control_ids(models)
        perimeter_lower = set(perimeter_map.keys())

        if exclude and not ids_were_provided:
            # ALL \ PERIMETER
            final_lower = set(all_map.keys()) - perimeter_lower
            canonical = [all_map[l] for l in final_lower if l in all_map]
            return sort_by_id(canonical)

        requested_lower = expand_ids_to_control_ids_lower(models, filter_obj)

        # Default base set is PERIMETER
        final_lower = set(perimeter_lower)

        if requested_lower:
            if exclude:
                # PERIMETER \ IDS
                final_lower -= requested_lower
            else:
                # PERIMETER ∩ IDS
                final_lower &= requested_lower

        canonical = [perimeter_map.get(l) or all_map.get(l) for l in final_lower]
        canonical = [c for c in canonical if isinstance(c, str)]
        return sort_by_id(canonical)

    # list_type == "ALL" (default)
    requested_lower = expand_ids_to_control_ids_lower(models, filter_obj)

    final_lower = set(all_map.keys())
    if requested_lower:
        if exclude:
            # ALL \ IDS
            final_lower -= requested_lower
        else:
            # ALL ∩ IDS
            final_lower &= requested_lower

    canonical = [all_map[l] for l in final_lower if l in all_map]
    return sort_by_id(canonical)

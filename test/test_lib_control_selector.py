import pytest

from tmxcaliber.lib.control_selector import (
    _canonical_id_map_from_iter,
    expand_ids_to_control_ids_lower,
    get_aws_data_perimeter_control_ids,
    resolve_control_ids,
)
from tmxcaliber.lib.filter import Filter
from tmxcaliber.lib.threatmodel_data import ThreatModelData


@pytest.fixture(autouse=True)
def reset_threatmodel_data_list():
    ThreatModelData.threatmodel_data_list = []
    yield
    ThreatModelData.threatmodel_data_list = []


def create_threatmodel(*, controls=None, scorecard=None):
    return ThreatModelData(
        {
            "metadata": {"name": "Model"},
            "feature_classes": {},
            "threats": {},
            "controls": controls or {},
            "control_objectives": {},
            "actions": {},
            "scorecard": scorecard if scorecard is not None else {},
        },
        add_to_list=False,
    )


def test_canonical_id_map_preserves_first_seen_case_and_skips_invalid_values():
    mapping = _canonical_id_map_from_iter(["Svc.C1", "svc.c1", "", None, 123, "Svc.C2"])

    assert mapping == {"svc.c1": "Svc.C1", "svc.c2": "Svc.C2"}


def test_get_aws_data_perimeter_control_ids_ignores_invalid_scorecard_shapes():
    models = [
        create_threatmodel(scorecard=[]),
        create_threatmodel(
            scorecard={
                "aws_data_perimeter": {
                    "NA": ["Svc.C999"],
                    "Perimeter": ["Svc.C1", 123],
                    "Ignored": "not-a-list",
                }
            }
        ),
    ]

    assert get_aws_data_perimeter_control_ids(models) == {"svc.c1": "Svc.C1"}


def test_expand_ids_to_control_ids_lower_expands_objective_ids_from_strings_and_lists():
    models = [
        create_threatmodel(
            controls={
                "Svc.C1": {"objective": "Svc.CO1"},
                "Svc.C2": {"objective": ["Svc.CO2", "Svc.CO3"]},
                "Svc.C3": {"objective": ["Svc.CO2"]},
                "Svc.C4": "invalid-control",
            }
        )
    ]

    expanded = expand_ids_to_control_ids_lower(models, Filter(ids="Svc.C1,Svc.CO2"))

    assert expanded == {"svc.c1", "svc.c2", "svc.c3"}


def test_resolve_control_ids_supports_all_list_type_include_and_exclude():
    models = [
        create_threatmodel(
            controls={
                "Svc.C1": {"objective": "Svc.CO1"},
                "Svc.C2": {"objective": ["Svc.CO2"]},
                "Svc.C3": {"objective": "Svc.CO2"},
            }
        )
    ]

    included = resolve_control_ids(
        models,
        list_type="ALL",
        filter_obj=Filter(ids="Svc.C1,Svc.CO2"),
        exclude=False,
        ids_were_provided=True,
    )
    excluded = resolve_control_ids(
        models,
        list_type="ALL",
        filter_obj=Filter(ids="Svc.CO2"),
        exclude=True,
        ids_were_provided=True,
    )

    assert included == ["Svc.C1", "Svc.C2", "Svc.C3"]
    assert excluded == ["Svc.C1"]


def test_resolve_control_ids_perimeter_excludes_requested_ids_when_provided():
    models = [
        create_threatmodel(
            controls={
                "Svc.C1": {"objective": "Svc.CO1"},
                "Svc.C2": {"objective": "Svc.CO2"},
                "Svc.C3": {"objective": "Svc.CO3"},
            },
            scorecard={
                "aws_data_perimeter": {"Perimeter": ["Svc.C1", "Svc.C2", "Svc.C3"]}
            },
        )
    ]

    ids = resolve_control_ids(
        models,
        list_type="AWS_DATA_PERIMETER",
        filter_obj=Filter(ids="Svc.C2"),
        exclude=True,
        ids_were_provided=True,
    )

    assert ids == ["Svc.C1", "Svc.C3"]

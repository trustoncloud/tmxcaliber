from tmxcaliber.lib.tools import sort_by_id, sort_dict_by_id, sort_dict_list_by_id


def test_sort_by_id_numeric_suffix_not_lexicographic():
    assert sort_by_id(["Svc.C2", "Svc.C10", "Svc.C1"]) == [
        "Svc.C1",
        "Svc.C2",
        "Svc.C10",
    ]


def test_sort_dict_by_id_preserves_value_and_orders_keys():
    inp = {"Svc.T10": {"v": 10}, "Svc.T2": {"v": 2}, "Svc.T1": {"v": 1}}
    out = sort_dict_by_id(inp)

    assert list(out.keys()) == ["Svc.T1", "Svc.T2", "Svc.T10"]
    assert out["Svc.T10"] == {"v": 10}
    assert out["Svc.T2"] == {"v": 2}
    assert out["Svc.T1"] == {"v": 1}


def test_sort_dict_list_by_id_extract_letters_and_number_priority():
    items = [
        {"identifier": "Svc.C1"},
        {"identifier": "Svc.A1"},
        {"identifier": "Svc.CO1"},
        {"identifier": "Svc.T1"},
        {"identifier": "Svc.FC1"},
    ]
    out = sort_dict_list_by_id(items, "identifier")
    assert [x["identifier"] for x in out] == [
        "Svc.FC1",
        "Svc.T1",
        "Svc.CO1",
        "Svc.C1",
        "Svc.A1",
    ]

import pytest
from unittest.mock import patch
from tmxcaliber.lib.feature_class_hierarchy import FeatureClassHierarchy
from tmxcaliber.lib.errors import FeatureClassCycleError
import networkx as nx


feature_classes_with_cycle = {
    "Someservice.FC1": {
        "class_relationship": [{"type": "parent", "class": "Someservice.FC2"}]
    },
    "Someservice.FC2": {
        "class_relationship": [{"type": "parent", "class": "Someservice.FC3"}]
    },
    "Someservice.FC3": {
        "class_relationship": [{"type": "parent", "class": "Someservice.FC1"}]
    },
}


def test_initialization_with_cycle():
    # Test that an exception is raised during initialization if there is a cycle
    with pytest.raises(FeatureClassCycleError):
        FeatureClassHierarchy(feature_classes_with_cycle)


feature_classes_direct_cycle = {
    "Someservice.FC1": {
        "class_relationship": [{"type": "parent", "class": "Someservice.FC1"}]
    }
}


def test_initialization_with_direct_cycle():
    # Test that an exception is raised during initialization if there is a cycle
    with pytest.raises(FeatureClassCycleError):
        FeatureClassHierarchy(feature_classes_direct_cycle)


# Mock data for testing
feature_classes_no_cycle = {
    "Someservice.FC1": {
        "class_relationship": [{"type": "parent", "class": "Someservice.FC2"}]
    },
    "Someservice.FC2": {"class_relationship": []},
}


@pytest.fixture
def hierarchy_no_cycle():
    return FeatureClassHierarchy(feature_classes_no_cycle)


def test_initialization_with_no_cycle():
    # Test that the graph is built and no exception is raised when there are no cycles
    hierarchy = FeatureClassHierarchy(feature_classes_no_cycle)
    assert isinstance(hierarchy.graph, nx.DiGraph)
    assert hierarchy.validate_no_cycles() is True


def test_add_feature_class(hierarchy_no_cycle):
    # Test adding a feature class without a parent
    hierarchy_no_cycle.add_feature_class("Someservice.FC3")
    assert "Someservice.FC3".lower() in hierarchy_no_cycle.graph.nodes()


def test_add_feature_class_with_parent(hierarchy_no_cycle):
    # Test adding a feature class with a parent
    hierarchy_no_cycle.add_feature_class("Someservice.FC3", "Someservice.FC2")
    assert "Someservice.FC3".lower() in hierarchy_no_cycle.graph.nodes()
    assert (
        "Someservice.FC2".lower(),
        "Someservice.FC3".lower(),
    ) in hierarchy_no_cycle.graph.edges()


def test_remove_feature_class(hierarchy_no_cycle):
    # Test removing a feature class
    hierarchy_no_cycle.add_feature_class("Someservice.FC3")
    hierarchy_no_cycle.remove_feature_class("Someservice.FC3")
    assert "Someservice.FC3".lower() not in hierarchy_no_cycle.graph.nodes()


def test_get_ancestors(hierarchy_no_cycle):
    # Test retrieving ancestors
    ancestors = hierarchy_no_cycle.get_ancestors("Someservice.FC1")
    assert "Someservice.FC2".lower() in ancestors


def test_get_descendants(hierarchy_no_cycle):
    # Test retrieving descendants
    descendants = hierarchy_no_cycle.get_descendants("Someservice.FC2")
    assert "Someservice.FC1".lower() in descendants


def test_cycle_detection_after_modification(hierarchy_no_cycle):
    # Test that adding a cycle after initialization is detected
    hierarchy_no_cycle.add_feature_class("Someservice.FC3", "Someservice.FC1")
    hierarchy_no_cycle.graph.add_edge(
        "Someservice.FC3".lower(), "Someservice.FC1".lower()
    )
    cycle_exists = not hierarchy_no_cycle.validate_no_cycles()
    assert cycle_exists


# Complex hierarchical data without cycles
feature_classes_complex = {
    "Root": {"class_relationship": []},
    "Root2": {"class_relationship": []},
    "Child1": {"class_relationship": [{"type": "parent", "class": "Root"}]},
    "Child2": {"class_relationship": [{"type": "parent", "class": "Root"}]},
    "Grandchild1": {"class_relationship": [{"type": "parent", "class": "Child1"}]},
    "Grandchild2": {
        "class_relationship": [
            {"type": "parent", "class": "Child1"},
            {"type": "parent", "class": "Child2"},
        ]
    },
    "Grandchild3": {
        "class_relationship": [
            {"type": "parent", "class": "Grandchild2"},
            {"type": "parent", "class": "GrandGrandchild1"},
        ]
    },
    "GrandGrandchild1": {
        "class_relationship": [
            {"type": "parent", "class": "Child1"},
            {"type": "parent", "class": "Grandchild1"},
        ]
    },
    "GrandGrandchild2": {
        "class_relationship": [
            {"type": "parent", "class": "Grandchild2"},
            {"type": "parent", "class": "Root"},
        ]
    },
}


@pytest.fixture
def hierarchy_complex() -> FeatureClassHierarchy:
    return FeatureClassHierarchy(feature_classes_complex)


def test_remove_descendants_no_descendants(hierarchy_complex):
    # Ensure no change when there are no descendants
    hierarchy_complex.remove_feature_classes_and_orphan_descendants(["Grandchild1"])
    assert "Grandchild1".lower() not in hierarchy_complex.graph.nodes()


def test_remove_descendants_single_parent(hierarchy_complex):
    # Removing all descendants of 'Child1' which should include 'Grandchild1'
    hierarchy_complex.remove_feature_classes_and_orphan_descendants(["Child1"])
    assert "Grandchild1".lower() not in hierarchy_complex.graph.nodes()
    assert "Grandchild2".lower() in hierarchy_complex.graph.nodes()
    assert "Child1".lower() not in hierarchy_complex.graph.nodes()


def execute_remove_test(hierarchy, nodes_to_remove, expected_removed_nodes):
    expected_remaining_nodes = set(hierarchy.graph.nodes()) - expected_removed_nodes
    hierarchy.remove_feature_classes_and_orphan_descendants(nodes_to_remove)
    actual_remaining_nodes = set(hierarchy.graph.nodes())
    assert expected_removed_nodes.isdisjoint(
        actual_remaining_nodes
    ), "Removed nodes test failed: Some nodes that should be removed are still present."
    assert (
        expected_remaining_nodes == actual_remaining_nodes
    ), "Remaining nodes test failed: The nodes that should remain do not match."


def test_remove_root_relations(hierarchy_complex):
    # Define expected nodes to remain and to be removed
    expected_removed_nodes = {
        "Child1".lower(),
        "Child2".lower(),
        "Grandchild1".lower(),
        "Grandchild2".lower(),
        "Grandchild3".lower(),
        "GrandGrandchild1".lower(),
        "GrandGrandchild2".lower(),
        "Root".lower(),
    }
    execute_remove_test(hierarchy_complex, ["Root"], expected_removed_nodes)


def test_complex_multi_parent_relations(hierarchy_complex):
    # Reset the graph to initial state for another test scenario
    hierarchy_complex.__init__(feature_classes_complex)
    expected_removed_nodes = {
        "Child1".lower(),
        "Grandchild1".lower(),
        "GrandGrandchild1".lower(),
    }
    execute_remove_test(hierarchy_complex, ["Child1"], expected_removed_nodes)

    # Reset the graph to initial state for another test scenario
    hierarchy_complex.__init__(feature_classes_complex)
    expected_removed_nodes = {"Grandchild2".lower()}
    execute_remove_test(hierarchy_complex, ["Grandchild2"], expected_removed_nodes)

    # Reset the graph to initial state for another test scenario
    hierarchy_complex.__init__(feature_classes_complex)
    expected_removed_nodes = {
        "Child1".lower(),
        "Child2".lower(),
        "Grandchild1".lower(),
        "Grandchild2".lower(),
        "Grandchild3".lower(),
        "GrandGrandchild1".lower(),
    }
    execute_remove_test(hierarchy_complex, ["Child1", "Child2"], expected_removed_nodes)

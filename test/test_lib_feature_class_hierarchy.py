import pytest
from unittest.mock import patch
from tmxcaliber.lib.feature_class_hierarchy import FeatureClassHierarchy
from tmxcaliber.lib.errors import FeatureClassCycleError
import networkx as nx

# Mock data for testing
feature_classes_no_cycle = {
    'Someservice.FC1': {'class_relationship': [{'type': 'parent', 'class': 'Someservice.FC2'}]},
    'Someservice.FC2': {'class_relationship': []}
}

@pytest.fixture
def hierarchy_no_cycle():
    return FeatureClassHierarchy(feature_classes_no_cycle)

def test_initialization_with_no_cycle():
    # Test that the graph is built and no exception is raised when there are no cycles
    hierarchy = FeatureClassHierarchy(feature_classes_no_cycle)
    assert isinstance(hierarchy.graph, nx.DiGraph)
    assert hierarchy.validate_no_cycles() is True

feature_classes_with_cycle = {
    'Someservice.FC1': {'class_relationship': [{'type': 'parent', 'class': 'Someservice.FC2'}]},
    'Someservice.FC2': {'class_relationship': [{'type': 'parent', 'class': 'Someservice.FC3'}]},
    'Someservice.FC3': {'class_relationship': [{'type': 'parent', 'class': 'Someservice.FC1'}]}
}
def test_initialization_with_cycle():
    # Test that an exception is raised during initialization if there is a cycle
    with pytest.raises(FeatureClassCycleError):
        FeatureClassHierarchy(feature_classes_with_cycle)

def test_add_feature_class(hierarchy_no_cycle):
    # Test adding a feature class without a parent
    hierarchy_no_cycle.add_feature_class('Someservice.FC3')
    assert 'Someservice.FC3' in hierarchy_no_cycle.graph.nodes()

def test_add_feature_class_with_parent(hierarchy_no_cycle):
    # Test adding a feature class with a parent
    hierarchy_no_cycle.add_feature_class('Someservice.FC3', 'Someservice.FC2')
    assert 'Someservice.FC3' in hierarchy_no_cycle.graph.nodes()
    assert ('Someservice.FC2', 'Someservice.FC3') in hierarchy_no_cycle.graph.edges()

def test_remove_feature_class(hierarchy_no_cycle):
    # Test removing a feature class
    hierarchy_no_cycle.add_feature_class('Someservice.FC3')
    hierarchy_no_cycle.remove_feature_class('Someservice.FC3')
    assert 'Someservice.FC3' not in hierarchy_no_cycle.graph.nodes()

def test_get_ancestors(hierarchy_no_cycle):
    # Test retrieving ancestors
    ancestors = hierarchy_no_cycle.get_ancestors('Someservice.FC1')
    assert 'Someservice.FC2' in ancestors

def test_get_descendants(hierarchy_no_cycle):
    # Test retrieving descendants
    descendants = hierarchy_no_cycle.get_descendants('Someservice.FC2')
    assert 'Someservice.FC1' in descendants

def test_cycle_detection_after_modification(hierarchy_no_cycle):
    # Test that adding a cycle after initialization is detected
    hierarchy_no_cycle.add_feature_class('Someservice.FC3', 'Someservice.FC1')
    hierarchy_no_cycle.graph.add_edge('Someservice.FC3', 'Someservice.FC1') 
    cycle_exists = not hierarchy_no_cycle.validate_no_cycles()
    assert cycle_exists

# Complex hierarchical data without cycles
feature_classes_complex = {
    'Root': {'class_relationship': []},
    'Child1': {'class_relationship': [{'type': 'parent', 'class': 'Root'}]},
    'Child2': {'class_relationship': [{'type': 'parent', 'class': 'Root'}]},
    'Grandchild1': {'class_relationship': [{'type': 'parent', 'class': 'Child1'}]},
    'Grandchild2': {'class_relationship': [{'type': 'parent', 'class': 'Child1'}, {'type': 'parent', 'class': 'Child2'}]}
}

@pytest.fixture
def hierarchy_complex():
    return FeatureClassHierarchy(feature_classes_complex)

def test_remove_descendants_no_descendants(hierarchy_complex):
    # Ensure no change when there are no descendants
    hierarchy_complex.remove_feature_class_and_orphan_descendants('Grandchild1')
    assert 'Grandchild1' not in hierarchy_complex.graph.nodes()

def test_remove_descendants_single_parent(hierarchy_complex):
    # Removing all descendants of 'Child1' which should include 'Grandchild1' and 'Grandchild2'
    hierarchy_complex.remove_feature_class_and_orphan_descendants('Child1')
    assert 'Grandchild1' not in hierarchy_complex.graph.nodes()
    assert 'Grandchild2' in hierarchy_complex.graph.nodes()
    assert 'Child1' not in hierarchy_complex.graph.nodes()

def test_complex_multi_parent_relations(hierarchy_complex):
    # 'Grandchild2' should not be removed unless both 'Child1' and 'Child2' are removed
    hierarchy_complex.remove_feature_class_and_orphan_descendants('Root')
    assert 'Grandchild2' not in hierarchy_complex.graph.nodes()
    assert 'Child1' not in hierarchy_complex.graph.nodes()
    assert 'Child2' not in hierarchy_complex.graph.nodes()
    assert 'Root' in hierarchy_complex.graph.nodes()

    # Reset the graph to initial state for another test scenario
    hierarchy_complex.__init__(feature_classes_complex)
    hierarchy_complex.remove_feature_class_and_orphan_descendants('Child1')
    # 'Grandchild2' should still exist because it has another parent 'Child2'
    assert 'Grandchild2' in hierarchy_complex.graph.nodes()
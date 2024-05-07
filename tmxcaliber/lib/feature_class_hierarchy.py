import networkx as nx
from .errors import FeatureClassCycleError

class FeatureClassHierarchy:
    def __init__(self, feature_classes):
        self.feature_classes = feature_classes
        self.graph = nx.DiGraph()
        self.build_graph()
        if not self.validate_no_cycles():
            cycle = nx.find_cycle(self.graph, orientation='original')
            raise FeatureClassCycleError(cycle)

    def build_graph(self):
        for class_id, data in self.feature_classes.items():
            for relation in data.get("class_relationship", []):
                if relation["type"] == "parent":
                    self.graph.add_edge(relation["class"], class_id)

    def add_feature_class(self, class_id, parent_id=None):
        self.graph.add_node(class_id)
        if parent_id:
            self.graph.add_edge(parent_id, class_id)

    def remove_feature_class(self, class_id):
        # This removes the node and all associated edges
        self.graph.remove_node(class_id)

    def get_ancestors(self, class_id):
        if class_id in self.graph:
            return list(nx.ancestors(self.graph, class_id))
        else:
            return []

    def get_descendants(self, class_id):
        if class_id in self.graph:
            return list(nx.descendants(self.graph, class_id))
        else:
            return []

    def validate_no_cycles(self):
        return nx.is_directed_acyclic_graph(self.graph)
    
    def remove_feature_class_and_orphan_descendants(self, class_id):
        # Remove the feature class itself
        self.remove_feature_class(class_id)

        # Recursively remove eligible descendants
        descendants = self.get_descendants(class_id)
        for desc_id in descendants:
            if all(ancestor not in self.graph.nodes for ancestor in self.get_ancestors(desc_id)):
                self.remove_feature_class_and_descendants(desc_id)
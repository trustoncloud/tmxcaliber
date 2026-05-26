from typing import Any

import networkx as nx

from .errors import FeatureClassCycleError

FeatureClassData = dict[str, Any]
NormalizedFeatureClasses = dict[str, dict[str, list[dict[str, str]]]]


def normalize_feature_class_data(
    feature_classes: dict[str, FeatureClassData],
) -> NormalizedFeatureClasses:
    normalized_fcs: NormalizedFeatureClasses = {}
    for fc, fc_data in feature_classes.items():
        normalized_relations = [
            {"type": relation["type"], "class": relation["class"].lower()}
            for relation in fc_data.get("class_relationship", [])
        ]
        normalized_fcs[fc.lower()] = {"class_relationship": normalized_relations}
    return normalized_fcs


class FeatureClassHierarchy:
    def __init__(self, feature_classes: dict[str, FeatureClassData]) -> None:
        self.feature_classes = normalize_feature_class_data(feature_classes)
        self.graph: Any = nx.DiGraph()
        self.build_graph()
        if not self.validate_no_cycles():
            cycle = nx.find_cycle(self.graph, orientation="original")
            raise FeatureClassCycleError(cycle)

    def build_graph(self) -> None:
        for class_id, data in self.feature_classes.items():
            self.add_feature_class(class_id.lower())
            for relation in data.get("class_relationship", []):
                if relation["type"] == "parent":
                    self.graph.add_edge(relation["class"], class_id.lower())

    def validate_no_cycles(self) -> bool:
        return bool(nx.is_directed_acyclic_graph(self.graph))

    def add_feature_class(self, class_id: str, parent_id: str | None = None) -> None:
        self.graph.add_node(class_id.lower())
        if parent_id:
            self.graph.add_edge(parent_id.lower(), class_id.lower())

    def remove_feature_class(self, class_id: str) -> None:
        if class_id.lower() in self.graph.nodes():
            self.graph.remove_node(class_id.lower())

    def get_ancestors(self, class_id: str) -> list[str]:
        if class_id.lower() in self.graph.nodes():
            return list(nx.ancestors(self.graph, class_id.lower()))
        return []

    def get_descendants(self, class_id: str) -> list[str]:
        if class_id.lower() in self.graph.nodes():
            return list(nx.descendants(self.graph, class_id.lower()))
        return []

    def remove_feature_classes_and_orphan_descendants(
        self, class_ids: list[str]
    ) -> None:
        normalized_class_ids = {class_id.lower() for class_id in class_ids}

        # A recursive function to remove a node and its orphan descendants
        def remove_with_orphans(class_id: str) -> None:
            if class_id not in self.graph:
                return
            if class_id in self.graph.nodes():
                descendants = set(nx.descendants(self.graph, class_id))
                self.remove_feature_class(class_id)

                for desc in descendants:
                    if desc in self.graph and not any(
                        ancestor in self.graph
                        for ancestor in nx.ancestors(self.graph, desc)
                    ):
                        remove_with_orphans(desc)

        # Remove each initial node and handle its orphans
        for class_id in normalized_class_ids:
            remove_with_orphans(class_id)

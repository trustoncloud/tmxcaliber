import io
import csv
import json
import copy
import logging
from typing import Optional, List
from .feature_class_hierarchy import FeatureClassHierarchy
from .tools import sort_by_id, sort_dict_by_id, apply_json_filter


class ThreatModelDataList:

    def __init__(self, threatmodel_data_list):
        self.threatmodel_data_list = threatmodel_data_list

    def get_csv(self):
        output = io.StringIO()
        fieldnames = ["id"] + list(
            self.threatmodel_data_list[0]
            .get_json()["threats"][
                next(iter(self.threatmodel_data_list[0].get_json()["threats"]))
            ]
            .keys()
        )
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for threatmodel_data in self.threatmodel_data_list:
            threats = threatmodel_data.threats
            for key, value in threats.items():
                value["access"] = json.dumps(value["access"])
                writer.writerow({"id": key, **value})
        return output


def get_permissions(access: dict | None, add_optional: bool = True) -> list[str]:
    """
    Extract a unique, lower-cased list of permissions from a ThreatModel `access` block.

    If add_optional is False, permissions under the OPTIONAL operator are ignored.
    """
    if not isinstance(access, dict):
        return []

    permissions: list[str] = []

    for key, perms in access.items():
        if not add_optional and key == "OPTIONAL":
            continue  # Skip optional permissions if add_optional is False

        if isinstance(perms, str):
            permissions.append(perms)
        elif isinstance(perms, list):
            for perm in perms:
                if isinstance(perm, str):
                    permissions.append(perm)
                elif isinstance(perm, dict):
                    permissions.extend(get_permissions(perm, add_optional))

    # Unique + normalised
    return sorted({x.lower() for x in permissions})


def upgrade_to_latest_template_version(tm_json):
    for co in tm_json.get("control_objectives", {}):
        co_data = tm_json["control_objectives"][co]
        if co_data.get("scf") and isinstance(co_data["scf"], str):
            tm_json["control_objectives"][co]["scf"] = co_data["scf"].split(",")

    # Due to a mistake on the ThreatModels
    for fc in tm_json.get("feature_classes", {}):
        if tm_json["feature_classes"][fc]["class_relationship"] == {}:
            tm_json["feature_classes"][fc]["class_relationship"] = []

    # Due to older version calling release time "timestamp"
    if tm_json.get("metadata"):
        if tm_json["metadata"].get("timestamp"):
            tm_json["metadata"]["release"] = tm_json["metadata"]["timestamp"]
    return tm_json


class ThreatModelData:

    threatmodel_data_list = []

    def __init__(self, threatmodel_json: dict, *, add_to_list: bool = True):
        upgraded_json = upgrade_to_latest_template_version(threatmodel_json)
        self.threatmodel_json_original = copy.deepcopy(upgraded_json)
        self.threatmodel_json = upgraded_json
        self.metadata = self.threatmodel_json.get("metadata")
        if self.metadata:
            self.release = self.metadata.get("release")
        self.threats = sort_dict_by_id(self.threatmodel_json.get("threats", {}))
        self.feature_classes = sort_dict_by_id(
            self.threatmodel_json.get("feature_classes", {})
        )
        self.original_feature_classes = sort_dict_by_id(
            self.threatmodel_json_original.get("feature_classes", {})
        )
        self.controls = sort_dict_by_id(self.threatmodel_json.get("controls", {}))
        self.control_objectives = sort_dict_by_id(
            self.threatmodel_json.get("control_objectives", {})
        )
        self.actions = sort_dict_by_id(self.threatmodel_json.get("actions", {}))
        if add_to_list:
            ThreatModelData.threatmodel_data_list.append(self)

    def get_feature_classes_not_fully_related(
        self, feature_class_ids_to_filter: list
    ) -> list:
        feature_class_hierarchy = FeatureClassHierarchy(self.original_feature_classes)

        for feature_class_id_to_filter in feature_class_ids_to_filter:
            actual_feature_class_id_to_filter = None
            for fc in self.feature_classes.keys():
                if fc.lower() == feature_class_id_to_filter.lower():
                    actual_feature_class_id_to_filter = fc
                    break

            if (
                not actual_feature_class_id_to_filter
                or actual_feature_class_id_to_filter not in self.feature_classes
            ):
                logging.warning(
                    f"[WARM] The provided FC id ({feature_class_id_to_filter}) is not present in {self.release}. Make sure to write the full ID, (e.g., Route53.FC1)"
                )

        feature_class_hierarchy.remove_feature_classes_and_orphan_descendants(
            feature_class_ids_to_filter
        )
        return list(set(feature_class_hierarchy.graph.nodes()))

    def get_ancestors_feature_classes(self, feature_class_id):
        feature_class_hierarchy = FeatureClassHierarchy(self.original_feature_classes)
        return list(set(feature_class_hierarchy.get_ancestors(feature_class_id)))

    def get_controls_for_current_threats(self) -> dict:
        controls: dict = {}
        threat_ids = set(self.threats.keys())
        for control_id, control in self.controls.items():
            feature_classes = control.get("feature_class", [])
            if not isinstance(feature_classes, list):
                feature_classes = []

            # Check if the control's feature class is in the list of feature classes
            if any(fc in feature_classes for fc in self.feature_classes):
                # Check if any mitigation in the control is related to the threats we have
                mitigate = control.get("mitigate", [])
                if not isinstance(mitigate, list):
                    mitigate = []

                if any(
                    isinstance(mitigation, dict)
                    and mitigation.get("threat") in threat_ids
                    for mitigation in mitigate
                ):
                    controls[control_id] = control

        for control_id, control in controls.copy().items():
            assured_by = control.get("assured_by") or ""
            if not isinstance(assured_by, str):
                assured_by = ""

            for assurance_control_id in assured_by.split(","):
                assurance_control_id = assurance_control_id.strip()
                if (
                    assurance_control_id
                    and assurance_control_id not in controls
                    and assurance_control_id in self.controls
                ):
                    controls[assurance_control_id] = self.controls[assurance_control_id]

        return sort_dict_by_id(controls)

    def get_upstream_dependent_controls(self, control_id) -> dict:

        def get_all_dependencies(controls, control_id, seen=None):
            if seen is None:
                seen = set()

            # Get the current control's data
            control_data = controls.get(control_id, {})
            depends_on = control_data.get("depends_on")
            # Check if depends_on contains multiple control IDs separated by commas
            if depends_on:
                depends_on_ids = depends_on.split(",")
                for depends_on_id in depends_on_ids:
                    depends_on_id = depends_on_id.strip()  # Clean up any whitespace
                    if depends_on_id and depends_on_id not in seen:
                        seen.add(depends_on_id)
                        get_all_dependencies(controls, depends_on_id, seen)

            return seen

        controls = {}
        for control_dependency_id in get_all_dependencies(self.controls, control_id):
            controls[control_dependency_id] = self.controls[control_dependency_id]
        return controls

    def get_downstream_dependent_controls(self, control_ids: list) -> dict:

        def build_reverse_dependencies(controls):
            reverse_deps = {}
            for ctrl_id, ctrl_data in controls.items():
                depends_on = ctrl_data.get("depends_on")
                if depends_on:
                    depends_on_ids = [
                        dep_id.strip() for dep_id in depends_on.split(",")
                    ]
                    for dep_id in depends_on_ids:
                        if dep_id.lower() not in reverse_deps:
                            reverse_deps[dep_id.lower()] = []
                        reverse_deps[dep_id.lower()].append(ctrl_id.lower())
            return reverse_deps

        def find_all_dependents(
            reverse_deps, initial_controls: list, all_controls, seen=None
        ):
            if seen is None:
                seen = set()

            # Initialize the search with all initial controls
            stack = list(initial_controls)

            while stack:
                current_control = stack.pop()
                if current_control in reverse_deps:
                    for dependent in reverse_deps[current_control]:
                        if dependent not in seen:
                            # Check if all dependencies of 'dependent' are in 'seen' or are among the initial controls
                            real_control_id = None
                            for control_id in all_controls:
                                if control_id.lower() == dependent:
                                    real_control_id = control_id
                                    break
                            dependent_data = all_controls[real_control_id]
                            if (
                                "depends_on" in dependent_data
                                and dependent_data["depends_on"]
                            ):
                                dependent_dependencies = [
                                    dep.strip()
                                    for dep in dependent_data["depends_on"]
                                    .lower()
                                    .split(",")
                                ]
                                if all(
                                    dep in seen or dep in initial_controls
                                    for dep in dependent_dependencies
                                ):
                                    seen.add(dependent)
                                    stack.append(dependent)
                            else:
                                # If no dependencies, we can add directly
                                seen.add(dependent)
                                stack.append(dependent)

            return seen

        reverse_dependencies = build_reverse_dependencies(self.controls)
        all_dependents = find_all_dependents(
            reverse_dependencies, control_ids, self.controls
        )
        return all_dependents

    def get_removed_output(self) -> dict:
        return apply_json_filter(self.threatmodel_json_original, self.get_json())

    def get_json(self) -> dict:
        json_data = {}
        # Iterate over the keys of the original threatmodel_json
        for key, value in self.threatmodel_json.items():
            if key == "threats":
                json_data[key] = self.threats
            elif key == "feature_classes":
                json_data[key] = self.feature_classes
            elif key == "controls":
                json_data[key] = self.controls
            elif key == "control_objectives":
                json_data[key] = self.control_objectives
            elif key == "actions":
                json_data[key] = self.actions
            else:
                json_data[key] = value
        return json_data

    @classmethod
    def get_csv_of_threats(cls):
        if not cls.threatmodel_data_list:
            return []

        first_threats = next(
            (
                threatmodel_data.get_json().get("threats", {})
                for threatmodel_data in cls.threatmodel_data_list
                if threatmodel_data.get_json().get("threats")
            ),
            None,
        )
        if not first_threats:
            return []

        fieldnames = ["id"] + list(first_threats[next(iter(first_threats))].keys())
        csv_matrix = []
        csv_matrix.append(fieldnames)
        for threatmodel_data in cls.threatmodel_data_list:
            threats = threatmodel_data.threats
            for key, value in threats.items():
                row_data = dict(value)
                row_data["id"] = key
                row_data["access"] = json.dumps(row_data["access"])
                row = [row_data.get(fieldname, "") for fieldname in fieldnames]
                csv_matrix.append(row)
        return csv_matrix

    @classmethod
    def _get_csv_of_controls_from_controls_dict(
        cls,
        threatmodel_data_list: list["ThreatModelData"],
        *,
        controls_by_tm: list[dict],
    ) -> list[list[str]]:
        if not threatmodel_data_list or not controls_by_tm:
            return []

        first_controls = next(
            (controls for controls in controls_by_tm if controls), None
        )
        if not first_controls:
            first_controls = next(
                (
                    controls
                    for threatmodel_data in threatmodel_data_list
                    for controls in [threatmodel_data.get_json().get("controls", {})]
                    if isinstance(controls, dict) and controls
                ),
                None,
            )
        if not first_controls:
            return []

        all_fieldnames = [
            field
            for field in first_controls[next(iter(first_controls))].keys()
            if field not in ("id", "objective", "objective_description", "retired")
        ]

        ordered_fieldnames = ["objective", "objective_description", "id"]
        ordered_fieldnames += all_fieldnames
        ordered_fieldnames.append("retired")

        csv_matrix: list[list[str]] = []
        csv_matrix.append(ordered_fieldnames)

        for threatmodel_data, controls in zip(threatmodel_data_list, controls_by_tm):
            control_objectives = threatmodel_data.get_json().get(
                "control_objectives", {}
            )

            for key, value in controls.items():
                objective_id = value.get("objective")
                co_description = ""
                if (
                    objective_id
                    and isinstance(control_objectives, dict)
                    and objective_id in control_objectives
                ):
                    co_description = control_objectives[objective_id].get(
                        "description", ""
                    )

                value["objective_description"] = co_description
                value["id"] = key
                row = [value.get(fieldname, "") for fieldname in ordered_fieldnames]
                csv_matrix.append(row)

        return csv_matrix

    @classmethod
    def get_csv_of_controls(
        cls, control_filter: Optional[List[str]] = None, exclude: bool = False
    ):
        if not cls.threatmodel_data_list:
            return []

        if not any(
            isinstance(threatmodel_data.get_json().get("controls"), dict)
            and threatmodel_data.get_json().get("controls")
            for threatmodel_data in cls.threatmodel_data_list
        ):
            return []

        controls_by_tm: list[dict] = []
        if control_filter is not None:
            filtered_set = {control_id.lower() for control_id in control_filter}

            for threatmodel_data in cls.threatmodel_data_list:
                tm_controls = threatmodel_data.get_json()["controls"]
                subset: dict = {}
                for control_id, control_data in tm_controls.items():
                    in_filter = control_id.lower() in filtered_set
                    if (exclude and not in_filter) or ((not exclude) and in_filter):
                        subset[control_id] = control_data
                controls_by_tm.append(sort_dict_by_id(subset))
        else:
            controls_by_tm = [
                threatmodel_data.get_json()["controls"]
                for threatmodel_data in cls.threatmodel_data_list
            ]

        return cls._get_csv_of_controls_from_controls_dict(
            cls.threatmodel_data_list, controls_by_tm=controls_by_tm
        )

    @classmethod
    def get_csv_of_aws_data_perimeter_controls(
        cls, control_filter: Optional[List[str]] = None, exclude: bool = False
    ):
        if not cls.threatmodel_data_list:
            return []

        control_ids = set()
        for threatmodel_data in cls.threatmodel_data_list:
            scorecard = threatmodel_data.get_json().get("scorecard") or {}
            aws_data_perimeter = scorecard.get("aws_data_perimeter") or {}
            if not isinstance(aws_data_perimeter, dict):
                continue
            for category, ids in aws_data_perimeter.items():
                if isinstance(category, str) and category.strip().lower() == "na":
                    continue
                if isinstance(ids, list):
                    for control_id in ids:
                        if isinstance(control_id, str):
                            control_ids.add(control_id)

        ids_list = list(control_ids)
        if control_filter:
            filtered_set = {control_id.lower() for control_id in control_filter}
            if exclude:
                ids_list = [
                    control_id
                    for control_id in ids_list
                    if control_id.lower() not in filtered_set
                ]
            else:
                ids_list = [
                    control_id
                    for control_id in ids_list
                    if control_id.lower() in filtered_set
                ]

        if ids_list:
            ids_list = sort_by_id(ids_list)

        ids_lower = {control_id.lower() for control_id in ids_list}

        controls_by_tm: list[dict] = []
        for threatmodel_data in cls.threatmodel_data_list:
            tm_controls = threatmodel_data.get_json().get("controls", {})
            subset: dict = {}
            for control_id, control_data in tm_controls.items():
                if control_id.lower() in ids_lower:
                    subset[control_id] = control_data
            controls_by_tm.append(sort_dict_by_id(subset))

        if not ids_list:
            return [["id"]]

        if not controls_by_tm or not any(controls_by_tm):
            return [["id"]]

        return cls._get_csv_of_controls_from_controls_dict(
            cls.threatmodel_data_list, controls_by_tm=controls_by_tm
        )


def get_classified_cvssed_control_ids_by_co(
    control_id_by_cvss_severity: "dict[str, list]",
    control_obj_id: str,
    control_data: dict,
) -> "dict[str, list]":
    severity_range = ("Very High", "High", "Medium", "Low", "Very Low")
    control_id_list = {}

    for idx, severity in enumerate(severity_range):
        if control_id_by_cvss_severity:
            control_id_list[severity] = control_id_by_cvss_severity[severity]
        else:
            control_id_list[severity] = []
        for control in control_data:
            if control_data[control]["objective"] != control_obj_id:
                continue
            if control_data[control]["weighted_priority"] != severity:
                continue
            add_control = True
            if control in control_id_list[severity]:
                add_control = False
            if idx > 0:
                for severity_prev in severity_range[0:idx]:
                    if control in control_id_list[severity_prev]:
                        add_control = False
            if add_control:
                control_id_list[severity].append(control)
        control_id_list[severity] = sort_by_id(control_id_list[severity])
    return control_id_list

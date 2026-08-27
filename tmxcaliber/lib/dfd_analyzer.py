"""drawio DFD parsing and analysis for ThreatModel DFDs.

Decodes a DFD ``body`` (base64 of the drawio ``<mxfile>`` XML, with an optional
base64 + raw-deflate ``<diagram>`` payload) and exposes the diagram model:
:class:`DfdAnalyzer` enumerates edge endpoints and the geometry-contained box
hierarchy. This is the single drawio codec in tmx; the other DFD modules build
on it.

DFD code map (tmx)
------------------
* ``tmx/datastore/dfd.py`` (storage): S3 I/O, manifests, buckets, presigned
  URLs, and ``Dfd.get_b64()``, which produces the body this module parses.
* ``tmx/dfd_analyzer.py`` (this module, parse): the drawio codec and
  ``DfdAnalyzer`` (edges, boxes, geometric trust-boundary containment).
* ``tmx/dfd_diff.py`` (diff): compares two parsed DFDs structurally for the
  tm_qa field-diffs, built on ``DfdAnalyzer``.
* ``tmx/tm_qa/tm_loader.py`` (load): loads the DFD manifest/XML for the tm_qa
  detectors (e23/e24/e165).

Consumers include ``threatmodel.py`` (which attaches a ``DfdAnalyzer`` to the
model), ``qa.py``, the tm_qa detectors, the JSON templates, and local tools.

A separate, standalone copy of the drawio codec also lives in the ``dfd-cli``
repo (``dfd/xml/main.py``); it is not shared because ``dfd-cli`` is its own
deployable tool.
"""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
import zlib
from urllib.parse import unquote


def is_mxfile_xml(value: str) -> bool:
    """
    Return True if `value` looks like XML and the top-level element is <mxfile>.
    This ignores leading whitespace and an optional XML declaration.
    """
    stripped = value.lstrip()
    if not stripped.startswith("<"):
        return False

    # Remove optional XML declaration, e.g. <?xml version="1.0" encoding="UTF-8"?>
    stripped = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", stripped, flags=re.IGNORECASE)

    return re.match(r"^<mxfile(\s|>)", stripped, flags=re.IGNORECASE) is not None


def is_base64_compressed_drawio(value: str) -> bool:
    """
    Return True if `value` looks like a base64-encoded, raw-DEFLATE-compressed draw.io
    payload
    that inflates into XML.

    This is a best-effort check: it attempts to base64-decode and raw-inflate the
    content and
    then checks whether the result looks like XML.
    """
    stripped = value.strip()

    # Quick reject: not base64-ish or too short to be meaningful.
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped) or len(stripped) < 16:
        return False

    try:
        compressed = base64.b64decode("".join(stripped.split()), validate=False)
        decompressed = zlib.decompress(compressed, wbits=-zlib.MAX_WBITS)
        text = decompressed.decode("utf-8", errors="strict")
    except Exception:
        return False

    return text.lstrip().startswith("<")


def _get_root_tag_attribute(xml_text: str, attribute_name: str) -> str | None:
    """
    Extract an attribute from the root XML element using a proper XML parser.

    Returns None if the input is not parseable XML or the attribute is not present.
    """
    stripped = xml_text.lstrip()
    if not stripped.startswith("<"):
        return None

    try:
        root = ET.fromstring(stripped)
    except ET.ParseError:
        return None

    return root.attrib.get(attribute_name)


def _is_truthy_xml_attr(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes"}


def _looks_like_base64(value: str) -> bool:
    stripped = value.strip()
    return (
        re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped) is not None and len(stripped) >= 16
    )


def _inflate_raw_deflate_base64(b64_value: str) -> str:
    compressed = base64.b64decode(b64_value, validate=False)
    decompressed = zlib.decompress(compressed, wbits=-zlib.MAX_WBITS)
    return decompressed.decode("utf-8", errors="strict")


def _maybe_url_decode_xml(value: str) -> str:
    """
    draw.io content sometimes ends up percent-encoded (URL-encoded), e.g.
    '%3CmxGraphModel...'.
    If it looks like that, decode it.
    """
    stripped = value.lstrip()
    if stripped.startswith("%3C") or stripped.startswith("%3c"):
        return unquote(value)

    # Heuristic: if it contains many percent-escapes and no '<', it's likely encoded
    # XML.
    if "<" not in value and re.search(r"%[0-9A-Fa-f]{2}", value) is not None:
        decoded = unquote(value)
        if decoded.lstrip().startswith("<"):
            return decoded

    return value


def _local_name(tag: str) -> str:
    """
    Return the local-name of an ElementTree tag, stripping any namespace.

    ElementTree represents namespaced tags as '{namespace}local'.
    """
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _get_object_label(obj: ET.Element | None) -> str | None:
    if obj is None:
        return None

    # draw.io stores the human label on the <object ... label="..."> wrapper
    label = obj.attrib.get("label")
    if label is not None and label.strip() != "":
        return label

    # Fallback: sometimes label is stored as "value"
    value = obj.attrib.get("value")
    if value is not None and value.strip() != "":
        return value

    return None


def _get_mxcell_geometry(cell: ET.Element) -> tuple[float, float, float, float] | None:
    """
    Return (x, y, width, height) for an mxCell if it has an mxGeometry child with those
    attributes.
    """
    for child in list(cell):
        if _local_name(child.tag) != "mxGeometry":
            continue
        x = child.attrib.get("x")
        y = child.attrib.get("y")
        w = child.attrib.get("width")
        h = child.attrib.get("height")
        if x is None or y is None or w is None or h is None:
            return None
        try:
            return (float(x), float(y), float(w), float(h))
        except ValueError:
            return None
    return None


def _rect_contains(
    outer: tuple[float, float, float, float], inner: tuple[float, float, float, float]
) -> bool:
    ox, oy, ow, oh = outer
    ix, iy, iw, ih = inner
    return (
        (ox <= ix)
        and (oy <= iy)
        and ((ox + ow) >= (ix + iw))
        and ((oy + oh) >= (iy + ih))
    )


def uncompress_drawio_diagram(value: str) -> str:
    """
    If `value` is an <mxfile ... compressed="true"> document, inflate the inner
    <diagram> payload
    (base64 + raw DEFLATE) and return the resulting XML (typically <mxGraphModel ...>).

    If the mxfile is not marked as compressed, or parsing/decompression fails, return
    `value`.
    """
    if not is_mxfile_xml(value):
        return value

    compressed_attr = _get_root_tag_attribute(value, "compressed")
    if not _is_truthy_xml_attr(compressed_attr):
        return value

    try:
        root = ET.fromstring(value.lstrip())
    except ET.ParseError:
        return value

    diagram = root.find(".//diagram")
    if diagram is None or diagram.text is None:
        return value

    diagram_text = diagram.text.strip()
    if not _looks_like_base64(diagram_text):
        return value

    try:
        inflated = _inflate_raw_deflate_base64("".join(diagram_text.split()))
        return _maybe_url_decode_xml(inflated)
    except Exception:
        return value


def uncompress_drawio_string_if_needed(value: str) -> str:
    """
    Normalise draw.io content into uncompressed XML.

    Supported inputs:
    1. <mxfile ... compressed="true"><diagram>BASE64+RAW-DEFLATE</diagram></mxfile>
       -> returns inflated XML from the <diagram> content.
    2. <mxfile ... compressed!="true">...</mxfile>
       -> returns the input unchanged.
    3. Base64-encoded XML (e.g. base64("<mxfile ...>...</mxfile>"))
       -> returns decoded XML (and inflates diagram if needed).
    4. A raw BASE64+RAW-DEFLATE payload
       -> returns inflated XML.
    """
    stripped = value.strip()

    if is_mxfile_xml(stripped):
        return _maybe_url_decode_xml(uncompress_drawio_diagram(stripped))

    # Base64-encoded XML
    if _looks_like_base64(stripped):
        try:
            decoded_bytes = base64.b64decode("".join(stripped.split()), validate=True)
            decoded_text = decoded_bytes.decode("utf-8", errors="strict")
            decoded_text = _maybe_url_decode_xml(decoded_text)
            if decoded_text.lstrip().startswith("<"):
                if is_mxfile_xml(decoded_text):
                    return _maybe_url_decode_xml(
                        uncompress_drawio_diagram(decoded_text)
                    )
                return decoded_text
        except Exception:
            pass

    # Raw base64 + raw-DEFLATE payload
    if is_base64_compressed_drawio(stripped):
        try:
            inflated = _inflate_raw_deflate_base64("".join(stripped.split()))
            return _maybe_url_decode_xml(inflated)
        except Exception:
            return value

    return _maybe_url_decode_xml(value)


class DfdAnalyzer:
    def __init__(self, tm_json_dfd_string: str | None = None) -> None:
        # Stored as the <mxGraphModel> element when available (preferred), otherwise the
        # parsed root.
        self.uncompressed_data: ET.Element | None = None
        if tm_json_dfd_string:
            self.load_from_string(dfd_string=tm_json_dfd_string)

    def load_from_string(self, dfd_string: str) -> None:
        xml_text = uncompress_drawio_string_if_needed(dfd_string)
        xml_text = _maybe_url_decode_xml(xml_text)
        try:
            parsed_root = ET.fromstring(xml_text.lstrip())
        except ET.ParseError:
            self.uncompressed_data = None
            return

        # Prefer storing the mxGraphModel element (works for both <mxfile> and direct
        # mxGraphModel).
        if parsed_root.tag == "mxGraphModel":
            self.uncompressed_data = parsed_root
            return

        mx_graph_model = parsed_root.find(".//mxGraphModel")
        self.uncompressed_data = (
            mx_graph_model if mx_graph_model is not None else parsed_root
        )

    def get_xml(self) -> str:
        if self.uncompressed_data is None:
            return ""
        return ET.tostring(self.uncompressed_data, encoding="unicode")

    def get_edge_endpoints(self) -> list[dict[str, str | bool | None]]:
        """
        Return a list describing each arrow/edge and the IDs of the boxes it connects.

        draw.io / mxGraphModel convention:
        - edges: <mxCell edge="1" ... source="..." target="...">
        - boxes: <mxCell vertex="1" id="...">

        In many draw.io exports (including your sample), edges are wrapped like:
            <object id="EDGE_ID"><mxCell edge="1" .../></object>
        and the <mxCell> itself may not have an id. In that case, we use the parent
        <object>'s id.

        Output items:
        - "edge_id": "...|None",
        - "label": "...|None",
        - "source_id": "...|None",
        - "target_id": "...|None",
        - "source_is_vertex": true|false,
        - "target_is_vertex": true|false,
        """
        if self.uncompressed_data is None:
            return []

        root = self.uncompressed_data

        # Build parent map so we can find ancestors of an <mxCell>.
        parent_by_child: dict[ET.Element, ET.Element] = {}
        for parent in root.iter():
            for child in list(parent):
                parent_by_child[child] = parent

        # Index all mxCells by id (for vertex checks). Namespace-agnostic.
        cell_by_id: dict[str, ET.Element] = {}
        for el in root.iter():
            if _local_name(el.tag) != "mxCell":
                continue
            cell_id = el.attrib.get("id")
            if cell_id:
                cell_by_id[cell_id] = el

        def is_vertex(cell_id: str | None) -> bool:
            if cell_id is None:
                return False
            cell = cell_by_id.get(cell_id)
            if cell is None:
                return False
            return cell.attrib.get("vertex") == "1"

        def get_ancestor_object(cell: ET.Element) -> ET.Element | None:
            current: ET.Element | None = cell
            while current is not None:
                parent = parent_by_child.get(current)
                if parent is None:
                    return None
                if _local_name(parent.tag) == "object":
                    return parent
                current = parent
            return None

        edges: list[dict[str, str | bool | None]] = []
        for cell in root.iter():
            if _local_name(cell.tag) != "mxCell":
                continue
            if cell.attrib.get("edge") != "1":
                continue

            parent_obj = get_ancestor_object(cell)

            # Edge id: prefer the wrapper <object id="..."> (matches your sample),
            # otherwise fall back to mxCell id.
            edge_id = None
            if parent_obj is not None:
                edge_id = parent_obj.attrib.get("id")
            if not edge_id:
                edge_id = cell.attrib.get("id")

            source_id = cell.attrib.get("source")
            target_id = cell.attrib.get("target")

            # Some exports may put source/target on the <object> wrapper.
            if parent_obj is not None:
                source_id = source_id or parent_obj.attrib.get("source")
                target_id = target_id or parent_obj.attrib.get("target")

            label = _get_object_label(parent_obj)

            edges.append(
                {
                    "edge_id": edge_id,
                    "label": label,
                    "threat": (
                        parent_obj.attrib.get("threat")
                        if parent_obj is not None
                        else None
                    ),
                    "feature_class": (
                        parent_obj.attrib.get("feature_class")
                        if parent_obj is not None
                        else None
                    ),
                    "source_id": source_id,
                    "target_id": target_id,
                    "source_is_vertex": is_vertex(source_id),
                    "target_is_vertex": is_vertex(target_id),
                }
            )
        return edges

    def get_top_boxes_with_contained_boxes(
        self,
        include_all_descendants: bool = False,
    ) -> list[dict[str, object]]:
        """
        Return all top-level boxes (vertex objects not contained by any other vertex
        object),
        and the boxes they contain.

        Containment is determined geometrically using mxGeometry rectangles.

        If `include_all_descendants` is False, each top box includes only its *direct*
        children
        (i.e. contained boxes that are not contained by another contained box).
        If True, each top box includes all descendants (any depth).

        Output format (per top box):
        {
            "object_id": str|None,
            "label": str|None,
            "feature_class": str|None,
            "threat": str|None,
            "mxcell_id": str|None,
            "x": float,
            "y": float,
            "width": float,
            "height": float,
            "contained": [ ... same structure for contained boxes ... ]
        }
        """
        if self.uncompressed_data is None:
            return []

        root = self.uncompressed_data

        # Build parent map so we can find the <object> wrapper for any <mxCell>.
        parent_by_child: dict[ET.Element, ET.Element] = {}
        for parent in root.iter():
            for child in list(parent):
                parent_by_child[child] = parent

        def get_ancestor_object(el: ET.Element) -> ET.Element | None:
            current: ET.Element | None = el
            while current is not None:
                parent = parent_by_child.get(current)
                if parent is None:
                    return None
                if _local_name(parent.tag) == "object":
                    return parent
                current = parent
            return None

        # Collect all vertex boxes with geometry.
        boxes: list[dict[str, object]] = []
        geoms: list[tuple[float, float, float, float]] = []
        for cell in root.iter():
            if _local_name(cell.tag) != "mxCell":
                continue
            if cell.attrib.get("vertex") != "1":
                continue

            geom = _get_mxcell_geometry(cell)
            if geom is None:
                continue

            obj = get_ancestor_object(cell)
            boxes.append(
                {
                    "object_id": obj.attrib.get("id") if obj is not None else None,
                    "label": _get_object_label(obj),
                    "feature_class": obj.attrib.get("feature_class")
                    if obj is not None
                    else None,
                    "threat": obj.attrib.get("threat") if obj is not None else None,
                    "mxcell_id": cell.attrib.get("id"),
                    "x": geom[0],
                    "y": geom[1],
                    "width": geom[2],
                    "height": geom[3],
                }
            )
            geoms.append(geom)

        if not boxes:
            return []

        # Determine containment relationships between boxes.
        # parent_of[i] = index of smallest box that contains i (direct parent), or None.
        parent_of: list[int | None] = [None] * len(boxes)

        for i in range(len(boxes)):
            geom_i = geoms[i]
            best_parent: int | None = None
            best_area: float | None = None

            for j in range(len(boxes)):
                if i == j:
                    continue
                geom_j = geoms[j]
                if not _rect_contains(geom_j, geom_i):
                    continue
                if geom_j == geom_i:
                    continue

                area_j = float(geom_j[2]) * float(geom_j[3])
                if best_area is None or area_j < best_area:
                    best_area = area_j
                    best_parent = j

            parent_of[i] = best_parent

        # Build children lists.
        children_of: dict[int, list[int]] = {i: [] for i in range(len(boxes))}
        for child_idx, parent_idx in enumerate(parent_of):
            if parent_idx is not None:
                children_of[parent_idx].append(child_idx)

        # Top boxes are those with no parent.
        top_indices = [i for i, p in enumerate(parent_of) if p is None]

        def build_tree(idx: int) -> dict[str, object]:
            node = dict(boxes[idx])
            if include_all_descendants:
                node["contained"] = [build_tree(child) for child in children_of[idx]]
            else:
                # Direct children only (already direct by construction).
                node["contained"] = [dict(boxes[child]) for child in children_of[idx]]
            return node

        # Sort top boxes by area descending (largest first) for readability.
        def area_idx(i: int) -> float:
            g = geoms[i]
            return float(g[2]) * float(g[3])

        top_indices.sort(key=area_idx, reverse=True)

        return [build_tree(i) for i in top_indices]

    def get_top_box_for_object_id(
        self, object_id: str
    ) -> dict[str, str | bool | None] | None:
        top_boxes = self.get_boxes_for_object_id(object_id, top_only=True)
        return top_boxes[0] if len(top_boxes) > 0 else None

    def get_boxes_for_object_id(
        self, object_id: str, top_only: bool = False
    ) -> list[dict[str, str | bool | None]]:
        """
        Return the *container boxes* that contain the given draw.io <object id="...">.

        This method uses the containment tree from `get_top_boxes_with_contained_boxes`
        to ensure
        that "top" really means a DFD top-level box (not just the largest container in a
        filtered list).

        If `top_only` is False:
        - returns the ancestor chain from the closest container up to the top-level
        container(s).

        If `top_only` is True:
        - returns only the top-level container box(es) that contain the object.

        Output items match the previous method:
        - "object_id": "...",
        - "container_object_id": "...|None",
        - "container_label": "...|None",
        - "container_feature_class": "...|None",
        - "container_threat": "...|None",
        - "mxcell_id": "...|None",
        - "is_vertex": true|false,
        - "x": "...|None",
        - "y": "...|None",
        - "width": "...|None",
        - "height": "...|None",
        """
        tree = self.get_top_boxes_with_contained_boxes(include_all_descendants=True)
        if not tree:
            return []

        def node_matches_target(node: dict[str, object]) -> bool:
            return (
                node.get("object_id") == object_id or node.get("mxcell_id") == object_id
            )

        def find_paths_to_target(
            node: dict[str, object],
            current_path: list[dict[str, object]],
        ) -> list[list[dict[str, object]]]:
            new_path = [*current_path, node]
            if node_matches_target(node):
                return [new_path]

            contained = node.get("contained")
            if not isinstance(contained, list):
                return []

            paths: list[list[dict[str, object]]] = []
            for child in contained:
                if not isinstance(child, dict):
                    continue
                paths.extend(find_paths_to_target(child, new_path))
            return paths

        all_paths: list[list[dict[str, object]]] = []
        for top in tree:
            if not isinstance(top, dict):
                continue
            all_paths.extend(find_paths_to_target(top, []))

        if not all_paths:
            return []

        # Convert a node to the legacy container dict format.
        def to_container_dict(node: dict[str, object]) -> dict[str, str | bool | None]:
            container_object_id = node.get("object_id")
            container_label = node.get("label")
            container_feature_class = node.get("feature_class")
            container_threat = node.get("threat")
            mxcell_id = node.get("mxcell_id")
            return {
                "object_id": object_id,
                "container_object_id": container_object_id
                if isinstance(container_object_id, str)
                else None,
                "container_label": container_label
                if isinstance(container_label, str)
                else None,
                "container_feature_class": container_feature_class
                if isinstance(container_feature_class, str)
                else None,
                "container_threat": container_threat
                if isinstance(container_threat, str)
                else None,
                "mxcell_id": mxcell_id if isinstance(mxcell_id, str) else None,
                "is_vertex": True,
                "x": str(node.get("x")) if node.get("x") is not None else None,
                "y": str(node.get("y")) if node.get("y") is not None else None,
                "width": str(node.get("width"))
                if node.get("width") is not None
                else None,
                "height": str(node.get("height"))
                if node.get("height") is not None
                else None,
            }

        # For each path, containers are the ancestors excluding the target node itself.
        # Path is [top, ..., target]. We want [closest_container, ..., top].
        containers: list[dict[str, str | bool | None]] = []
        for path in all_paths:
            if len(path) <= 1:
                continue
            ancestor_nodes = path[:-1]  # exclude target
            # reverse so closest container first
            for node in reversed(ancestor_nodes):
                containers.append(to_container_dict(node))

        if not containers:
            return []

        if top_only:
            # Return only the top-level container(s) for each path (deduplicated).
            top_containers: list[dict[str, str | bool | None]] = []
            seen: set[str] = set()
            for path in all_paths:
                top_node = path[0]
                top_id = top_node.get("object_id")
                key = (
                    str(top_id)
                    if top_id is not None
                    else f"mxcell:{top_node.get('mxcell_id')}"
                )
                if key in seen:
                    continue
                seen.add(key)
                top_containers.append(to_container_dict(top_node))
            return top_containers

        # Deduplicate while preserving order (closest-first across paths).
        seen_keys: set[str] = set()
        deduped: list[dict[str, str | bool | None]] = []
        for item in containers:
            key = f"{item.get('container_object_id')}|{item.get('mxcell_id')}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped.append(item)

        return deduped

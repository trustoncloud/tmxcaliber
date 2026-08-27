"""Semantic diff for drawio DFD bodies, used by tm_qa field-diffs.

A ThreatModel DFD ``body`` (``get_vanilla_json()["dfd"]["body"]``) is base64
of the drawio ``<mxfile>`` XML. Comparing those base64 strings (or the raw
XML) reports a change on every save, because drawio rewrites volatile editor
state on each export: the ``<mxfile>`` ``etag`` / ``modified`` / ``agent`` /
``version`` attributes and the ``<mxGraphModel>`` ``dx`` / ``dy`` viewport
offset. None of that is a real diagram change, which is why a naive body
comparison flags every TM on every run.

This module decodes and parses each body with
:class:`tmxcaliber.lib.dfd_analyzer.DfdAnalyzer`
(the project's drawio parser, already used by ``ThreatModel``) and compares the
resulting cells. Each node and edge is keyed by its drawio ``id`` (stable
across edits) and fingerprinted on the attributes that define the diagram's
structure: the label, the container (the trust-boundary box that geometrically
encloses it), and, for edges, the endpoints. Everything else is excluded as
noise:

* Absolute geometry (``x`` / ``y`` / ``width`` / ``height``) and ``style`` are
  layout and presentation, not a data-flow change, and move/recolor on routine
  edits. Boundary membership is derived from geometry but only changes when a
  node actually crosses into or out of a boundary box, so panning, scaling, or
  jitter that preserves containment is ignored.
* The TrustOnCloud ``threat`` / ``feature_class`` annotations are *derived*:
  the DFD pipeline recomputes them from the threat sheet, so they shift on
  every threat/feature-class update even when the diagram is untouched. Those
  changes are already reported as ``threats.*`` / ``feature_classes.*`` field
  diffs, so counting them here would double-report and make the DFD look
  changed on routine OverWatch updates.

The result is a structured :class:`DfdDiff` describing what changed, or
``None`` when the diagrams are structurally equivalent. Comparison is over the
diagram model that ``DfdAnalyzer`` exposes (the first page); TrustOnCloud
service DFDs are single-page.

See the DFD code map in ``tmxcaliber/lib/dfd_analyzer.py`` for how this module fits with
the storage and parse layers.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from tmxcaliber.lib.dfd_analyzer import DfdAnalyzer

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

# Cap the number of per-cell lines in a change summary so a large diagram
# cannot write an unbounded value into ``tm_field_diffs``.
_SUMMARY_CAP = 30


class DfdDecodeError(ValueError):
    """Raised when a non-empty DFD body cannot be decoded to a graph model."""


@dataclass(frozen=True)
class DfdCell:
    """A normalized, comparable DFD cell (a node or an edge).

    Identity is the drawio ``cell_id``, which is stable across edits. Absolute
    geometry, ``style``, and the derived ``threat`` / ``feature_class``
    annotations are deliberately absent: only structure (kind, label, the
    enclosing trust-boundary box, and edge endpoints) defines a cell here.
    """

    cell_id: str
    kind: str  # "vertex" | "edge"
    label: str
    container: str  # id of the boundary box geometrically enclosing it ("" = top level)
    source: str  # edges only
    target: str  # edges only

    def fingerprint(self) -> tuple[str, ...]:
        """Return the tuple compared to decide whether a cell was modified."""
        return (self.kind, self.label, self.container, self.source, self.target)

    def display(self) -> str:
        """Return a short human label for change summaries."""
        if self.label:
            return self.label
        if self.kind == "edge":
            ends = " -> ".join(p for p in (self.source, self.target) if p)
            if ends:
                return f"edge {ends}"
        return f"{self.kind} {self.cell_id}"


@dataclass(frozen=True)
class DfdDiff:
    """Outcome of comparing two DFD bodies (only built when they differ)."""

    change_type: str  # "added" | "removed" | "modified"
    added: tuple[str, ...]
    removed: tuple[str, ...]
    modified: tuple[str, ...]
    old_node_count: int
    old_edge_count: int
    new_node_count: int
    new_edge_count: int

    def summary_new(self) -> str:
        """Return a readable summary of the draft-side delta (``new_value``)."""
        if self.change_type == "added":
            return (
                f"DFD added ({self.new_node_count} nodes, {self.new_edge_count} edges)"
            )
        if self.change_type == "removed":
            return "DFD removed"
        header = (
            f"{len(self.added)} added, {len(self.removed)} removed, "
            f"{len(self.modified)} changed"
        )
        lines = [header]
        lines.extend(_capped(self.added, "+"))
        lines.extend(_capped(self.removed, "-"))
        lines.extend(_capped(self.modified, "~"))
        return "\n".join(lines)

    def summary_old(self) -> str:
        """Return a readable summary of the prod baseline (``old_value``)."""
        if self.change_type == "added":
            return "no DFD"
        return f"DFD: {self.old_node_count} nodes, {self.old_edge_count} edges"


def _capped(items: tuple[str, ...], prefix: str) -> list[str]:
    """Render up to ``_SUMMARY_CAP`` items as ``"<prefix> <item>"`` lines."""
    lines = [f"{prefix} {item}" for item in items[:_SUMMARY_CAP]]
    overflow = len(items) - _SUMMARY_CAP
    if overflow > 0:
        lines.append(f"... (+{overflow} more)")
    return lines


def _clean_label(raw: str) -> str:
    """Normalize a drawio label for comparison.

    Strips HTML tags, unescapes entities, and collapses whitespace so a
    formatting-only difference (for example ``<br>`` versus a newline) does
    not register as a semantic change.
    """
    if not raw:
        return ""
    text = raw.replace("&#xa;", " ").replace("\n", " ")
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def _collect_vertices(
    nodes: list[dict[str, object]],
    container_id: str,
    out: dict[str, DfdCell],
) -> None:
    """Flatten ``DfdAnalyzer``'s containment tree into ``out`` keyed by id.

    Each node records the id of the box that geometrically encloses it.
    """
    for node in nodes:
        cell_id = str(node.get("object_id") or node.get("mxcell_id") or "")
        if cell_id:
            out[cell_id] = DfdCell(
                cell_id=cell_id,
                kind="vertex",
                label=_clean_label(str(node.get("label") or "")),
                container=container_id,
                source="",
                target="",
            )
        children = node.get("contained")
        if isinstance(children, list):
            _collect_vertices(children, cell_id, out)


def normalize_dfd_body(body: str | None) -> dict[str, DfdCell]:
    """Decode a DFD body to its comparable cells keyed by drawio id.

    Args:
        body: base64 of the drawio ``<mxfile>`` XML, or ``None`` / empty.

    Returns:
        A mapping of cell id to :class:`DfdCell`; empty for an empty body.

    Raises:
        DfdDecodeError: if a non-empty body cannot be decoded.
    """
    if not body or not body.strip():
        return {}
    analyzer = DfdAnalyzer(tm_json_dfd_string=body)
    if analyzer.uncompressed_data is None:
        raise DfdDecodeError("DFD body could not be decoded to a graph model")

    cells: dict[str, DfdCell] = {}
    _collect_vertices(
        analyzer.get_top_boxes_with_contained_boxes(include_all_descendants=True),
        "",
        cells,
    )
    for edge in analyzer.get_edge_endpoints():
        edge_id = str(edge.get("edge_id") or "")
        if not edge_id:
            continue
        cells[edge_id] = DfdCell(
            cell_id=edge_id,
            kind="edge",
            label=_clean_label(str(edge.get("label") or "")),
            container="",
            source=str(edge.get("source_id") or ""),
            target=str(edge.get("target_id") or ""),
        )
    return cells


def _counts(cells: dict[str, DfdCell]) -> tuple[int, int]:
    """Return ``(node_count, edge_count)`` for a cell mapping."""
    nodes = sum(1 for c in cells.values() if c.kind == "vertex")
    edges = sum(1 for c in cells.values() if c.kind == "edge")
    return nodes, edges


def diff_dfd_bodies(old_body: str | None, new_body: str | None) -> DfdDiff | None:
    """Compare two DFD bodies, ignoring volatile editor and layout state.

    Args:
        old_body: the prod (READY_FOR_RELEASE) DFD body, or ``None``.
        new_body: the draft DFD body, or ``None``.

    Returns:
        A :class:`DfdDiff` when the diagrams differ semantically, or ``None``
        when they are equivalent (including when both are empty).

    Raises:
        DfdDecodeError: if either non-empty body cannot be decoded.
    """
    old_cells = normalize_dfd_body(old_body)
    new_cells = normalize_dfd_body(new_body)
    if not old_cells and not new_cells:
        return None

    old_ids = set(old_cells)
    new_ids = set(new_cells)
    added_ids = new_ids - old_ids
    removed_ids = old_ids - new_ids
    modified_ids = {
        cid
        for cid in old_ids & new_ids
        if old_cells[cid].fingerprint() != new_cells[cid].fingerprint()
    }
    if not added_ids and not removed_ids and not modified_ids:
        return None

    if not old_cells:
        change_type = "added"
    elif not new_cells:
        change_type = "removed"
    else:
        change_type = "modified"

    old_nodes, old_edges = _counts(old_cells)
    new_nodes, new_edges = _counts(new_cells)
    return DfdDiff(
        change_type=change_type,
        added=tuple(sorted(new_cells[c].display() for c in added_ids)),
        removed=tuple(sorted(old_cells[c].display() for c in removed_ids)),
        modified=tuple(sorted(new_cells[c].display() for c in modified_ids)),
        old_node_count=old_nodes,
        old_edge_count=old_edges,
        new_node_count=new_nodes,
        new_edge_count=new_edges,
    )

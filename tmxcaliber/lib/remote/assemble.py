"""Rebuild a canonical ThreatModel document from the API.

The API serves a model in five pieces: a detail route carrying the sections
that are small, three paged collections, and the data flow diagram. The
canonical schema requires all eight top-level sections, so a caller that
wants a document tmxcaliber can work on has to put them back together.

**Every call is pinned to one release, and that is the point.** The detail
route reports the release it answered with, and the four others are asked
for that exact release. Without the pin, a model republished part-way
through the read would be stitched together out of two versions into a
document that still validates against the schema and is wrong.
"""

from __future__ import annotations

from typing import Any

from ..threatmodel_data import ThreatModelData
from .client import TocClient
from .errors import ContractViolation, NotFound
from .ref import TmRef

#: The sections the detail route omits, each served by its own route.
#:
#: Ordered as the canonical schema lists them, so a diff between an
#: assembled document and a published one reads cleanly.
PARTS = ("threats", "controls", "actions")


def _detail_path(ref: TmRef) -> str:
    """Build the detail route's path.

    Args:
        ref: The ThreatModel.

    Returns:
        The path.
    """
    return f"/v1/threatmodels/{ref.provider}/{ref.service}"


def fetch_document(client: TocClient, ref: TmRef) -> dict[str, Any]:
    """Assemble one ThreatModel from the API.

    Args:
        client: The configured client.
        ref: The ThreatModel, optionally pinned to a release.

    Returns:
        The canonical document, with every section the schema requires.

    Raises:
        NotFound: If the model, or the pinned release, is not available to
            this credential.
        ContractViolation: If the API answers in a shape the document cannot
            be built from.
        RemoteError: On any transport or server failure.
    """
    base = _detail_path(ref)
    pinned = {"release": ref.release} if ref.release else {}
    detail = client.get(base, pinned)

    # **Check the answer is the one that was asked for, before anything is
    # built on it or written to disk.** A proxy or a server-side identity
    # slip that returned a different model would otherwise be assembled,
    # cached under the requested reference, and then read back as fact for
    # as long as the cache lives.
    answered = str(detail.get("tmId") or "")
    if answered and answered.lower() != ref.tm_id.lower():
        raise ContractViolation(
            f"{base} answered for {answered}, not {ref.tm_id}.",
            code="wrong_model",
        )

    # The release the detail route actually answered with. Pinning the rest
    # of the read to this, rather than to what the caller asked for, is what
    # closes the window: "latest" is resolved once, here, and never again.
    release = str(detail.get("version") or "")
    if not release:
        raise ContractViolation(
            f"{base} did not name the release it answered with, so the "
            "remaining sections cannot be pinned to it.",
            code="unpinnable",
        )
    if ref.release and release != ref.release:
        raise ContractViolation(
            f"{base} answered with release {release}, not the requested {ref.release}.",
            code="wrong_release",
        )
    at_release = {"release": release}

    document: dict[str, Any] = {
        key: value for key, value in detail.items() if key not in {"tmId", "version"}
    }

    for part in PARTS:
        rows = list(client.paginate(f"{base}/{part}", at_release))
        document[part] = _by_id(part, rows)

    document["dfd"] = client.get(f"{base}/dfd", at_release)

    # The metadata carries its own version, and the cache is keyed from it
    # for an unpinned read. Two answers that disagree about which release
    # this is would be filed under the wrong one.
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        stated = str(metadata.get("version") or "")
        if stated and stated != release:
            raise ContractViolation(
                f"{base} answered as release {release} while its metadata "
                f"says {stated}.",
                code="release_disagreement",
            )
    return document


def _by_id(part: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Turn a collection's rows back into the document's id-keyed object.

    The API publishes each row with its identity as a named field, because a
    list needs one. The stored document keys the object by that identity
    instead, and the canonical schema describes the stored shape.

    Args:
        part: Which section, used to pick the id field and to report errors.
        rows: The rows as the API served them.

    Returns:
        The section, keyed by entity id.

    Raises:
        ContractViolation: If a row carries no identity.
    """
    field = {"threats": "threatId", "controls": "controlId", "actions": "actionId"}[
        part
    ]
    section: dict[str, Any] = {}
    for row in rows:
        identity = row.get(field)
        if not identity:
            raise ContractViolation(
                f"a {part[:-1]} arrived with no {field}.", code="row_without_id"
            )
        body = {key: value for key, value in row.items() if key != field}
        section[str(identity)] = body
    return section


def load_remote(client: TocClient, ref: TmRef) -> ThreatModelData:
    """Fetch a ThreatModel and wrap it the way the rest of the CLI expects.

    Args:
        client: The configured client.
        ref: The ThreatModel.

    Returns:
        The model.

    Raises:
        NotFound: If the model is not available to this credential.
        RemoteError: On any transport or server failure.
    """
    document = fetch_document(client, ref)
    # `add_to_list=False` on purpose: ThreatModelData keeps a class-level
    # registry that every construction appends to, so assembling several
    # models would leak them into whatever ran next.
    return ThreatModelData(document, add_to_list=False)


__all__ = ["PARTS", "NotFound", "fetch_document", "load_remote"]

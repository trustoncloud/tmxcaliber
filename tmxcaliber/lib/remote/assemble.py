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

from typing import Any, NamedTuple

from ...schema.schema import (
    threatmodel_required_metadata,
    threatmodel_required_sections,
)
from ..threatmodel_data import ThreatModelData
from .client import TocClient
from .contract import page_maximum
from .errors import ContractViolation, NotFound
from .ref import TmRef, is_release

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


class Fetched(NamedTuple):
    """An assembled document and the release it came from.

    **The release is carried beside the document, not inside it.** The
    canonical ``metadata.version`` is the template schema version, a date
    such as ``20240423``, and a release key is an epoch such as
    ``1611187200``. They are different facts with similar names, and reading
    one as the other files a document under a key nothing will look for.

    Attributes:
        document: The canonical document.
        release: The release the API answered with.
    """

    document: dict[str, Any]
    release: str


def fetch_document(client: TocClient, ref: TmRef) -> Fetched:
    """Assemble one ThreatModel from the API.

    Args:
        client: The configured client.
        ref: The ThreatModel, optionally pinned to a release.

    Returns:
        The canonical document, with every section the schema requires,
        and the release it was read at.

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
    if not answered:
        # Absent is not "assume it is the right one". A response with no
        # identity would be combined with collections requested for this
        # model and cached under this reference, which is the same wrong
        # document as naming another model, arrived at more quietly.
        raise ContractViolation(
            f"{base} answered without naming which ThreatModel it is.",
            code="unidentified",
        )
    if answered.lower() != ref.tm_id.lower():
        raise ContractViolation(
            f"{base} answered for {answered}, not {ref.tm_id}.",
            code="wrong_model",
        )

    # **Everything knowable from this one response is decided here**, before
    # the four calls that build on it. The metadata checks used to sit after
    # them, so a response with no metadata cost five calls to reject instead
    # of one, and the cross-check below was skipped entirely rather than
    # failing when there was nothing to cross-check against.
    metadata = detail.get("metadata")
    if not isinstance(metadata, dict):
        raise ContractViolation(
            f"{base} answered without metadata.", code="incomplete_metadata"
        )
    # A present section is not a populated one. `list services` reads
    # `service_name` with `.get`, so a missing one drops the model from the
    # listing rather than failing, and a pinned entry holds that for a week.
    #
    # Checked here rather than by validating the whole document, because the
    # published corpus does not satisfy its own schema in every detail.
    # Metadata is the exception: every published model carries all of these.
    # **`str()` was the hole here.** Coercing first made `None` into the
    # string "None", which is truthy, so a null field passed the very check
    # written to catch an empty one. The schema types all six as strings
    # and the published corpus holds strings, so ask for one.
    thin = [
        field
        for field in threatmodel_required_metadata()
        if not isinstance(metadata.get(field), str) or not metadata[field].strip()
    ]
    if thin:
        raise ContractViolation(
            f"{base} answered with metadata missing {', '.join(thin)}.",
            code="incomplete_metadata",
        )

    # The metadata names the same model a second time, and the two must
    # agree: a document whose body belongs to another service would
    # otherwise pass on the strength of a correct envelope alone. No longer
    # conditional, because metadata is now known to be there.
    stated = f"{metadata['provider']}-{metadata['service']}".lower()
    if stated != ref.tm_id.lower():
        raise ContractViolation(
            f"{base} answered with a document describing {stated}, not {ref.tm_id}.",
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
    if not is_release(release):
        # The server names the release, and the release becomes a filename.
        # Every other check here asks whether the answer is the right one;
        # this asks whether it is safe to act on.
        raise ContractViolation(
            f"{base} answered with a release that cannot be used as a name.",
            code="unusable_release",
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
        # The largest page the contract allows, read from the contract. The
        # server's default is smaller, and the difference is whole extra
        # calls per section against an hourly budget a single assembly
        # already spends five of.
        largest = page_maximum(f"/v1/threatmodels/{{provider}}/{{service}}/{part}") or 0
        rows = list(client.paginate(f"{base}/{part}", at_release, page_size=largest))
        document[part] = _by_id(part, rows)

    dfd = client.get(f"{base}/dfd", at_release)
    # An empty object is a dict, so the section check below would pass it,
    # and `generate` then fails on the missing body while the cache keeps
    # serving the same answer until it expires. The schema requires a
    # body; a diagram with no body is not one.
    if not isinstance(dfd.get("body"), str) or not dfd["body"].strip():
        raise ContractViolation(
            f"{base}/dfd answered without a diagram body.",
            code="empty_dfd",
        )
    document["dfd"] = dfd

    # **`metadata.release` is written here because nothing else writes it.**
    # `change_log.generate_change_log` reads `metadata["release"]` directly,
    # and the published document does not carry one: it is added by the
    # per-customer stamp on the delivery path, which this API does not
    # apply. Without this the documented remote `create-change-log` raises
    # KeyError on a response that is otherwise perfectly valid.
    #
    # Safe to write rather than a guess: it is the release the detail route
    # named, already checked against the pin and against the grammar.
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        document["metadata"] = {**metadata, "release": release}

    # **Complete, or not written at all.** Every check above asks whether
    # this is the right document; this one asks whether it is a whole one.
    # A detail response missing `metadata` or `control_objectives` passed
    # all of them, cached, and then read back as a model whose services or
    # mappings are simply empty, with nothing anywhere saying why.
    #
    # Structural rather than a schema validation: the published corpus does
    # not satisfy its own schema in every detail, so validating here would
    # reject real documents while this catches the truncation that matters.
    missing = [
        section
        for section in threatmodel_required_sections()
        if not isinstance(document.get(section), dict)
    ]
    if missing:
        raise ContractViolation(
            f"{base} did not yield a whole ThreatModel; "
            f"{', '.join(missing)} is missing or not an object.",
            code="incomplete_document",
        )

    return Fetched(document, release)


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
        # A real string, not something that can be printed. The stored
        # document keys this section by the identity, so anything else
        # becomes a nonsense key that still looks like a valid document.
        if not isinstance(identity, str) or not identity.strip():
            raise ContractViolation(
                f"a {part[:-1]} arrived with no usable {field}.",
                code="row_without_id",
            )
        if identity in section:
            # Assigning would drop the first one silently, and the walk
            # that produced it would still look complete. The rows are
            # sorted by this key and paged on it, so a repeat means the
            # page boundary moved under the read.
            raise ContractViolation(
                f"{part} contained {identity} twice.", code="duplicate_row"
            )
        section[identity] = {key: value for key, value in row.items() if key != field}
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
    fetched = fetch_document(client, ref)
    # `add_to_list=False` on purpose: ThreatModelData keeps a class-level
    # registry that every construction appends to, so assembling several
    # models would leak them into whatever ran next.
    return ThreatModelData(fetched.document, add_to_list=False)


__all__ = ["PARTS", "NotFound", "fetch_document", "load_remote"]

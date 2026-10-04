"""Rebuilding a canonical document, and the release pin that makes it sound."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from tmxcaliber.lib.remote.assemble import fetch_document, load_remote
from tmxcaliber.lib.remote.errors import ContractViolation
from tmxcaliber.lib.remote.ref import TmRef
from tmxcaliber.schema.schema import validate_threatmodel_schema

DETAIL = {
    "tmId": "aws-s3",
    "version": "1611187200",
    "metadata": {
        "provider": "aws",
        "service": "s3",
        "service_name": "Amazon S3",
        # The canonical template schema version, as every published
        # document carries it. Deliberately not the release: they are
        # different facts with similar names.
        "version": "20240423",
        "scf_version": "2025.3.1",
        "license": "CC BY-SA 4.0",
    },
    "scorecard": {},
    "feature_classes": {
        "S3.FC1": {
            "name": "Object operations",
            "class_relationship": [],
            "description": "Object operations.",
            "long_description": "Object operations, at length.",
            "order": 1,
            "retired": False,
        }
    },
    "control_objectives": {
        "S3.CO1": {
            "description": "Enforce encryption in transit",
            "scf": ["CRY-03"],
            "retired": False,
        }
    },
}

#: One row per section, carrying exactly what the canonical schema requires.
#:
#: Shaped from the published aws-s3 document rather than invented, because a
#: fixture that satisfies a weaker shape than the real corpus would let the
#: assembler produce documents the schema rejects.
PARTS: dict[str, list[dict[str, Any]]] = {
    "threats": [
        {
            "threatId": "S3.T1",
            "feature_class": "S3.FC1",
            "name": "Bucket takeover",
            "description": "An attacker recreates a deleted bucket name.",
            "access": {"OPTIONAL": "s3:DeleteBucket"},
            "hlgoal": "DataTheft",
            "mitre_attack": "TA0009,T1586",
            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "retired": False,
            "cvss_severity": "Medium",
            "cvss_score": 5.2,
        }
    ],
    "controls": [
        {
            "controlId": "S3.C1",
            "coso": "Preventative",
            "nist_csf": "Protect",
            "objective": "S3.CO1",
            "retired": False,
            "description": "Block all unencrypted requests.",
            "testing": "Make an unencrypted call; it should fail.",
            "effort": "Low",
            "mitigate": [
                {
                    "threat": "S3.T1",
                    "impact": "High",
                    "priority": 4.0,
                    # The published corpus carries null here, which the
                    # canonical schema types as a number. Kept numeric so this
                    # fixture tests the assembler rather than that mismatch.
                    "max_dependency": 4.0,
                    "priority_overall": 4.0,
                    "cvss": "Medium",
                }
            ],
            "feature_class": ["S3.FC1"],
            "weighted_priority": "High",
            "weighted_priority_score": 3,
            "queryable_objective_id": 1,
            "queryable_id": 1,
        }
    ],
    "actions": [
        {
            "actionId": "S3.A1",
            "action_description": "Aborts a multipart upload.",
            "api": "AbortMultipartUpload",
            "endpoint": "s3",
            "feature_class": "S3.FC1",
            "feature_class_action_type": "other",
            "iam_permission": "s3:AbortMultipartUpload",
            "event_name": "Data-AWS::S3::Object-AbortMultipartUpload",
            "stage": "ga",
            "action_id_int": 1,
            "retired": False,
        }
    ],
}

DFD = {"body": "PG14ZmlsZT48L214ZmlsZT4="}


def _at_release(detail: dict[str, Any], asked: str | None) -> dict[str, Any]:
    """Answer a detail call as the release it was asked for.

    Args:
        detail: The base detail fixture.
        asked: The release the caller pinned, if any.

    Returns:
        The detail document, naming the requested release.
    """
    answer = dict(detail)
    if asked:
        # Only the API's own field. `metadata.version` is the schema date
        # and does not move with the release.
        answer["version"] = asked
    return answer


class StubClient:
    """A client that answers from fixtures and records what it was asked."""

    def __init__(
        self, detail: dict[str, Any] | None = None, *, honour_release: bool = True
    ) -> None:
        self.detail = dict(DETAIL if detail is None else detail)
        # A well-behaved server answers for the release it was asked for.
        # Setting this False is how a test plays one that does not.
        self.honour_release = honour_release
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.page_sizes: list[int] = []
        self.dfd: dict[str, Any] = dict(DFD)

    key: str = "KEYONE"

    @property
    def base_url(self) -> str:
        """The endpoint, for cache keying.

        Returns:
            A stable fake.
        """
        return "https://api.example.test"

    @property
    def key_id(self) -> str:
        """Which credential this stub speaks as.

        Returns:
            The fake key id.
        """
        return self.key

    def get(self, path: str, params: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Answer a single-resource call.

        Args:
            path: The path.
            params: The query.

        Returns:
            The fixture for that path.
        """
        self.calls.append((path, dict(params or {})))
        if path.endswith("/dfd"):
            return dict(self.dfd)
        # A real detail route answers for the release it was asked for, and
        # the assembler refuses an answer that names a different one.
        asked = dict(params or {}).get("release")
        return _at_release(self.detail, asked if self.honour_release else None)

    def paginate(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        page_size: int = 0,
    ) -> Iterator[dict[str, Any]]:
        """Answer a collection call.

        Args:
            path: The path.
            params: The query.
            page_size: Ignored.

        Yields:
            The fixture rows for that path.
        """
        self.calls.append((path, dict(params or {})))
        self.page_sizes.append(page_size)
        yield from PARTS[path.rsplit("/", 1)[-1]]


def test_the_assembled_document_satisfies_the_canonical_schema() -> None:
    # The whole point of the exercise: eight sections, as the schema requires.
    document = fetch_document(StubClient(), TmRef("aws", "s3")).document  # type: ignore[arg-type]

    assert sorted(document) == [
        "actions",
        "control_objectives",
        "controls",
        "dfd",
        "feature_classes",
        "metadata",
        "scorecard",
        "threats",
    ]
    validate_threatmodel_schema(document)


def test_the_sections_are_keyed_by_entity_id() -> None:
    # The API publishes an identity field because a list needs one; the
    # stored document keys the object by it instead.
    document = fetch_document(StubClient(), TmRef("aws", "s3")).document  # type: ignore[arg-type]

    assert list(document["threats"]) == ["S3.T1"]
    assert document["threats"]["S3.T1"]["name"] == "Bucket takeover"
    assert "threatId" not in document["threats"]["S3.T1"]


def test_every_call_is_pinned_to_one_release() -> None:
    # **The unsoundness this closes.** Five calls across a republish would
    # stitch two releases into a document that still validates.
    client = StubClient()

    fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]

    subsequent = [params for path, params in client.calls[1:]]
    assert subsequent, "the detail call was the only one made"
    assert all(p.get("release") == "1611187200" for p in subsequent), client.calls


def test_the_caller_s_pin_is_sent_on_the_detail_call() -> None:
    client = StubClient()

    fetch_document(client, TmRef("aws", "s3", "1600000000"))  # type: ignore[arg-type]

    assert client.calls[0][1] == {"release": "1600000000"}


def test_latest_is_resolved_once_rather_than_per_call() -> None:
    # Every subsequent call names the release, so none of them re-resolves
    # what "latest" meant.
    client = StubClient()

    fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]

    assert client.calls[0][1] == {}
    assert len(client.calls) == 5


def test_an_unpinnable_answer_is_refused() -> None:
    # A detail route that does not name its release cannot be reassembled
    # safely, and guessing would reintroduce exactly the straddle.
    detail = {k: v for k, v in DETAIL.items() if k != "version"}
    client = StubClient(detail)

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert "pinned" in str(caught.value)


def test_a_row_without_an_identity_is_refused() -> None:
    client = StubClient()
    PARTS["threats"].append({"name": "nameless"})
    try:
        with pytest.raises(ContractViolation):
            fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    finally:
        PARTS["threats"].pop()


def test_loading_does_not_leak_into_the_shared_registry() -> None:
    # ThreatModelData keeps a class-level list that every construction
    # appends to, so a fetch loop would leak models into whatever ran next.
    from tmxcaliber.lib.threatmodel_data import ThreatModelData

    before = len(ThreatModelData.threatmodel_data_list)

    load_remote(StubClient(), TmRef("aws", "s3"))  # type: ignore[arg-type]

    assert len(ThreatModelData.threatmodel_data_list) == before


def test_a_document_for_another_model_is_refused() -> None:
    """A proxy or server-side identity slip must not be cached as fact.

    Without this the wrong document is assembled, filed under the requested
    reference, and read back as correct for as long as the cache lives.
    """
    client = StubClient({**DETAIL, "tmId": "aws-ec2"})

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert "aws-ec2" in str(caught.value)


def test_a_release_other_than_the_one_pinned_is_refused() -> None:
    # Answering a different version of the right model is the same problem
    # one level down, and the cache would file it under the pin.
    client = StubClient({**DETAIL, "version": "9999"}, honour_release=False)

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3", "1611187200"))  # type: ignore[arg-type]
    assert "9999" in str(caught.value)


def test_a_schema_version_is_not_mistaken_for_a_release() -> None:
    """`metadata.version` is the template schema date, not the release.

    Published documents carry `20240423` there while a release key is an
    epoch such as `1611187200`. Reading one as the other made every real
    document fail assembly, and filed every model under one cache name.
    """
    fetched = fetch_document(StubClient(), TmRef("aws", "s3"))  # type: ignore[arg-type]

    assert fetched.document["metadata"]["version"] == "20240423"
    assert fetched.release == "1611187200"
    assert fetched.release != fetched.document["metadata"]["version"]


def test_a_document_that_names_no_model_is_refused() -> None:
    """Absent identity is not "assume it is the right one".

    A response with no `tmId` would be combined with collections requested
    for this model and cached under this reference: the same wrong
    document, arrived at more quietly.
    """
    client = StubClient({k: v for k, v in DETAIL.items() if k != "tmId"})

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert "without naming" in str(caught.value)


def test_a_document_whose_metadata_describes_another_service_is_refused() -> None:
    # A correct envelope around the wrong body must not pass on the
    # envelope alone.
    detail = {
        **DETAIL,
        "metadata": {**DETAIL["metadata"], "provider": "gcp", "service": "storage"},
    }
    client = StubClient(detail)

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert "gcp-storage" in str(caught.value)


def test_a_detail_response_with_no_metadata_is_refused_on_the_first_call() -> None:
    """Rejected before the four calls that would build on it.

    The metadata checks used to run after them, so a response with no
    metadata cost five calls to reject instead of one, and the
    provider/service cross-check was skipped rather than failing when
    there was nothing to cross-check against.
    """
    client = StubClient({k: v for k, v in DETAIL.items() if k != "metadata"})

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]

    assert "without metadata" in str(caught.value)
    assert len(client.calls) == 1, "it kept fetching after the answer was unusable"


@pytest.mark.parametrize("field", ["service_name", "scf_version", "license"])
def test_metadata_missing_a_required_field_is_refused(field: str) -> None:
    """A present section is not a populated one.

    `list services` reads `service_name` with `.get`, so a missing one
    drops the model from the listing rather than failing.
    """
    thin = {k: v for k, v in DETAIL["metadata"].items() if k != field}
    client = StubClient({**DETAIL, "metadata": thin})

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]

    assert field in str(caught.value)
    assert len(client.calls) == 1


def test_each_collection_is_walked_at_the_contract_maximum() -> None:
    # The server default is smaller, and the difference is whole extra
    # calls per section against an hourly budget a single assembly already
    # spends five of.
    client = StubClient()

    fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]

    walked = [p for p, _ in client.calls if p.rsplit("/", 1)[-1] in PARTS]
    assert len(walked) == 3
    assert client.page_sizes == [500, 500, 500], client.page_sizes


@pytest.mark.parametrize("missing", ["control_objectives", "scorecard"])
def test_an_incomplete_document_is_refused_before_it_caches(missing: str) -> None:
    """Complete, or not written at all.

    Every other check asks whether this is the right document; this one
    asks whether it is a whole one. A detail response missing a section
    passed them all, cached, and then read back as a model whose services
    or mappings are simply empty with nothing saying why.
    """
    client = StubClient({k: v for k, v in DETAIL.items() if k != missing})

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert missing in str(caught.value)
    assert "whole ThreatModel" in str(caught.value)


def test_the_required_sections_come_from_the_schema() -> None:
    # Read from the canonical schema rather than written out here, so a
    # section added or removed there needs no second edit.
    from tmxcaliber.schema.schema import threatmodel_required_sections

    assert set(threatmodel_required_sections()) == {
        "actions",
        "control_objectives",
        "controls",
        "dfd",
        "feature_classes",
        "metadata",
        "scorecard",
        "threats",
    }


@pytest.mark.parametrize("release", ["/tmp/target", "../../../tmp/evil", "..", ""])
def test_a_release_that_could_act_as_a_path_is_refused(release: str) -> None:
    """The server names the release, and the release becomes a filename.

    `pathlib` discards everything left of an absolute component, so an
    unchecked release here is an arbitrary-write primitive driven by the
    API's answer. Refused where the other "do not trust the answer" checks
    live, so it costs one call rather than five.
    """
    client = StubClient({**DETAIL, "version": release}, honour_release=False)

    with pytest.raises(ContractViolation):
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]


def test_a_caller_cannot_type_a_dangerous_release_either() -> None:
    # The reference grammar already excluded a slash, which is why the gap
    # was only ever on the server's side. `..` slipped through until now.
    from tmxcaliber.lib.remote.ref import parse_ref

    for value in ["aws-s3@..", "aws-s3@."]:
        with pytest.raises(ValueError):
            parse_ref(value)


def test_the_assembled_document_carries_the_release_change_logs_need() -> None:
    """`generate_change_log` reads `metadata["release"]` directly.

    The published document has no such field: it is added by the
    per-customer stamp on the delivery path, which the API does not apply.
    Without stamping it here the documented remote `create-change-log`
    raises KeyError on a response that is otherwise perfectly valid.
    """
    fetched = fetch_document(StubClient(), TmRef("aws", "s3"))  # type: ignore[arg-type]

    assert fetched.document["metadata"]["release"] == fetched.release
    # The schema version is a different fact and is left alone.
    assert fetched.document["metadata"]["version"] == "20240423"


def test_a_change_log_between_two_remote_releases_runs() -> None:
    """The documented remote command, end to end.

    It was written up in the README as the payoff of release pinning and
    never actually exercised against an assembled document, which is how
    the missing release went unnoticed.
    """
    from tmxcaliber.lib.change_log import generate_change_log

    older = fetch_document(  # type: ignore[arg-type]
        StubClient(), TmRef("aws", "s3", "1600000000")
    ).document
    newer = fetch_document(  # type: ignore[arg-type]
        StubClient(), TmRef("aws", "s3", "1611187200")
    ).document

    change_log = generate_change_log(older, newer)

    assert change_log is not None


@pytest.mark.parametrize("value", [None, "", "   ", 42, [], {}])
def test_a_metadata_field_that_is_not_a_real_string_is_refused(value: object) -> None:
    """`str()` coercion was the hole this closes.

    Coercing first turned `None` into the string "None", which is truthy,
    so a null field passed the very check written to catch an empty one.
    The schema types all six as strings.
    """
    thin = {**DETAIL["metadata"], "service_name": value}
    client = StubClient({**DETAIL, "metadata": thin})

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert "service_name" in str(caught.value)


@pytest.mark.parametrize("body", [None, "", "  ", 0, []])
def test_a_dfd_without_a_usable_body_is_refused(body: object) -> None:
    """An empty object is still a dict, so the section check passes it.

    `generate` then fails on the missing body while the cache keeps
    serving the same answer until it expires. A diagram with no body is
    not a diagram.
    """
    client = StubClient()
    client.dfd = {"body": body} if body is not None else {}  # type: ignore[attr-defined]

    with pytest.raises(ContractViolation) as caught:
        fetch_document(client, TmRef("aws", "s3"))  # type: ignore[arg-type]
    assert "diagram body" in str(caught.value)


@pytest.mark.parametrize("identity", [None, "", "  ", 7, {"a": 1}])
def test_a_row_without_a_usable_identity_is_refused(identity: object) -> None:
    # The stored document keys the section by this value, so anything that
    # is merely printable becomes a nonsense key in a document that still
    # looks valid.
    PARTS["threats"].append({"threatId": identity, "name": "x"})
    try:
        with pytest.raises(ContractViolation):
            fetch_document(StubClient(), TmRef("aws", "s3"))  # type: ignore[arg-type]
    finally:
        PARTS["threats"].pop()


def test_a_repeated_row_is_refused_rather_than_overwriting() -> None:
    """Assigning twice would drop the first silently.

    The walk that produced it would still look complete, and the rows are
    sorted and paged on this key, so a repeat means the page boundary
    moved under the read.
    """
    PARTS["threats"].append(dict(PARTS["threats"][0]))
    try:
        with pytest.raises(ContractViolation) as caught:
            fetch_document(StubClient(), TmRef("aws", "s3"))  # type: ignore[arg-type]
        assert "twice" in str(caught.value)
    finally:
        PARTS["threats"].pop()

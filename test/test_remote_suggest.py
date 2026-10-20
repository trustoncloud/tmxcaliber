"""Telling someone which pack or ThreatModel a mistyped name probably meant."""

from __future__ import annotations

import pathlib
import re

import pytest

from tmxcaliber.lib.remote.suggest import (
    ALIASES,
    did_you_mean,
    normalize,
    suggest,
    suggest_provider,
)

#: Every CCR pack ccr_factory publishes, as its ``services.json`` names them.
KEYS: tuple[str, ...] = (
    "aws-s3",
    "azure-storage",
    "gcp-bigquery",
    "aws-transfer",
    "azure-keyvault",
    "gcp-pubsub",
    "aws-ec2",
    "aws-autoscaling",
    "azure-sql",
    "aws-eks",
    "aws-bedrock",
    "gcp-gke",
    "gcp-vertex",
    "gcp-notebooks",
    "aws-secretsmanager",
    "gcp-cloudsql",
    "aws-bedrockagentcore",
    "gcp-cloudkms",
    "gcp-iam",
    "gcp-compute",
)

#: Every ThreatModel the catalogue published when this was written, which is the
#: list the ``threatmodels`` commands suggest from. It is a far larger and more
#: crowded set than the packs, and the same name can exist under several
#: providers, so it shows what the short pack list cannot.
THREATMODEL_IDS: tuple[str, ...] = tuple(
    pathlib.Path(__file__).with_name("threatmodel_ids.txt").read_text().splitlines()
)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Amazon EC2", "ec2"),
        ("  Google_Cloud  SQL ", "cloud-sql"),
        ("pub/sub", "pub-sub"),
        ("Gemini Agent Platform", "gemini-agent-platform"),
        ("aws-ec2", "ec2"),
        ("Microsoft Azure Key Vault", "key-vault"),
        ("vertex--ai", "vertex-ai"),
        # A vendor word alone is the whole name, so it is kept.
        ("aws", "aws"),
        ("Google", "google"),
    ],
)
def test_a_name_is_normalized(name: str, expected: str) -> None:
    assert normalize(name) == expected


def test_every_alias_is_stored_normalized_and_names_a_release_key() -> None:
    release_key = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
    for name, keys in ALIASES.items():
        assert normalize(name) == name
        assert keys
        assert all(release_key.fullmatch(key) for key in keys)


def test_every_published_pack_has_an_alias() -> None:
    named = {key for keys in ALIASES.values() for key in keys}

    assert named >= set(KEYS)


def test_the_renamed_vertex_ai_is_an_alias() -> None:
    # Google renamed Vertex AI, and the ThreatModel and the pack keep the key
    # gcp-vertex, so the new name has to lead there.
    assert ALIASES["gemini-agent-platform"] == ("gcp-vertex",)
    assert ALIASES["vertex-ai"] == ("gcp-vertex",)


@pytest.mark.parametrize(
    ("query", "first"),
    [
        ("ec3", "aws-ec2"),
        ("aws-ec3", "aws-ec2"),
        ("bigqeury", "gcp-bigquery"),
        ("keyvalt", "azure-keyvault"),
        ("vertexai", "gcp-vertex"),
        ("s4", "aws-s3"),
        ("Gemini Agent Platform", "gcp-vertex"),
        ("gemini-agent-platform", "gcp-vertex"),
        ("Amazon EC2", "aws-ec2"),
        ("pub/sub", "gcp-pubsub"),
    ],
)
def test_a_near_name_suggests_its_key_first(query: str, first: str) -> None:
    assert suggest(query, KEYS)[0] == first


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("bigqeury", ["gcp-bigquery"]),
        ("keyvalt", ["azure-keyvault"]),
        ("vertexai", ["gcp-vertex"]),
        ("s4", ["aws-s3"]),
        ("Gemini Agent Platform", ["gcp-vertex"]),
        ("Amazon EC2", ["aws-ec2"]),
        ("pub/sub", ["gcp-pubsub"]),
        # The provider prefix counts, so the packs of the same provider whose
        # service is closest come next.
        ("aws-ec3", ["aws-ec2", "aws-s3", "aws-eks"]),
    ],
)
def test_a_near_name_suggests_only_what_is_close(
    query: str, expected: list[str]
) -> None:
    assert suggest(query, KEYS) == expected


def test_an_alias_whose_pack_is_not_a_candidate_suggests_nothing() -> None:
    readable = [key for key in KEYS if key != "gcp-vertex"]

    assert suggest("Gemini Agent Platform", readable) == []
    assert suggest("Gemini Agent Platform", ["aws-s3", "aws-ec2"]) == []


@pytest.mark.parametrize("query", ["kubernetesx-zzz", "lambda", ""])
def test_an_unrelated_word_suggests_nothing(query: str) -> None:
    assert suggest(query, KEYS) == []


@pytest.mark.parametrize("query", ["aws-ec2", "gcp-vertex"])
def test_a_name_that_is_a_candidate_suggests_nothing(query: str) -> None:
    assert suggest(query, KEYS) == []


@pytest.mark.parametrize("query", ["AWS-EC2", "aws_ec2", " aws ec2 "])
def test_a_key_typed_another_way_suggests_that_key_alone(query: str) -> None:
    # Spelled the way keys are spelled, it is that key, so the keys that merely
    # share its provider would only be noise beside it.
    assert suggest(query, KEYS) == ["aws-ec2"]


@pytest.mark.parametrize("query", ["aws", "Azure", "gcp", "Amazon AWS"])
def test_a_vendor_alone_suggests_nothing(query: str) -> None:
    # A vendor names no service, and the keys closest to it in spelling are
    # just its shortest ones, which would read as a guess.
    assert suggest(query, KEYS) == []


def test_the_threatmodels_spelling_and_googles_are_both_aliases() -> None:
    # The gcp-vertex ThreatModel spells the product "Collab Enterprise", and
    # Google spells it "Colab Enterprise". Each is an exact alias, so neither
    # depends on a near miss to reach the pack.
    assert ALIASES["collab-enterprise"] == ("gcp-vertex",)
    assert ALIASES["colab-enterprise"] == ("gcp-vertex",)


@pytest.mark.parametrize("query", ["Collab Enterprise", "Colab Enterprise"])
def test_either_spelling_of_colab_enterprise_reaches_vertex(query: str) -> None:
    assert suggest(query, KEYS) == ["gcp-vertex"]


def test_a_slip_in_colab_enterprise_still_reaches_vertex() -> None:
    # A near miss of the alias, which no longer carries either spelling alone.
    assert suggest("Colaab Enterprise", KEYS) == ["gcp-vertex"]


@pytest.mark.parametrize(
    ("query", "first"),
    [
        # The names people shorten a service to, which no spelling rule reaches.
        ("kms", "gcp-cloudkms"),
        ("Key Management Service", "gcp-cloudkms"),
        ("gemini", "gcp-vertex"),
        ("gcp-gemini", "gcp-vertex"),
        ("Gemini Enterprise", "gcp-vertex"),
        # The first words of a longer name, which is how a name is cut short.
        ("gemini agent", "gcp-vertex"),
        ("gemini-agent", "gcp-vertex"),
        ("Gemini Enterprise Agent", "gcp-vertex"),
        ("elastic kubernetes", "aws-eks"),
        ("agent", "aws-bedrockagentcore"),
    ],
)
def test_a_shortened_name_suggests_its_pack_first(query: str, first: str) -> None:
    assert suggest(query, KEYS)[0] == first


@pytest.mark.parametrize(
    ("query", "first"),
    [
        ("kms", "gcp-cloudkms"),
        ("gcp-gemini", "gcp-vertex"),
        ("gemini agent", "gcp-vertex"),
    ],
)
def test_a_shortened_name_is_led_to_its_threatmodel_among_hundreds(
    query: str, first: str
) -> None:
    assert suggest(query, THREATMODEL_IDS)[0] == first


def test_a_shortened_name_names_every_provider_that_has_one() -> None:
    # aws-kms is the KMS of AWS and gcp-cloudkms is Google's, and both are the
    # ThreatModels of a service called KMS.
    assert {"aws-kms", "gcp-cloudkms"} <= set(suggest("kms", THREATMODEL_IDS))


@pytest.mark.parametrize("query", ["agen", "kubernet"])
def test_a_piece_of_a_word_does_not_begin_an_alias(query: str) -> None:
    # The words of an alias are compared whole: "agen" is the start of "agent
    # core" letter for letter, and still names none of its words.
    assert suggest(query, KEYS) == []


def test_a_name_that_is_an_alias_is_not_taken_for_the_start_of_a_longer_one() -> None:
    # "ec2" begins the alias "ec2 auto scaling" and is an alias itself, so it
    # means EC2 alone.
    assert suggest("Amazon EC2", KEYS) == ["aws-ec2"]


@pytest.mark.parametrize(
    ("query", "expected"),
    [("aws-iamm", "aws-iam"), ("gcp-iamm", "gcp-iam"), ("Amazon IAMM", "aws-iam")],
)
def test_the_provider_typed_wins_over_another_providers_alias(
    query: str, expected: str
) -> None:
    # Both providers have an IAM, and the alias for "iam" leads to Google's.
    readable = ["aws-iam", "gcp-iam", "aws-acm"]

    found = suggest(query, readable)

    assert found[0] == expected
    assert {key.partition("-")[0] for key in found} == {expected.partition("-")[0]}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("gcp-storge", "gcp-storage"),
        ("gcp-cloudstorage", "gcp-storage"),
        ("Google Cloud Storage", "gcp-storage"),
        ("azure-storge", "azure-storage"),
    ],
)
def test_a_provider_and_a_service_of_two_providers_keeps_the_provider(
    query: str, expected: str
) -> None:
    # "storage" is an alias of azure-storage, and gcp-storage is the pack of
    # Google's. Naming Google must not lead to Azure's.
    readable = ["azure-storage", "gcp-storage", "aws-s3"]

    assert suggest(query, readable) == [expected]


@pytest.mark.parametrize(
    ("query", "first"),
    [
        ("aws-iamm", "aws-iam"),
        ("gcp-storge", "gcp-storage"),
        ("gcp-kms", "gcp-cloudkms"),
        ("gcp-gemini", "gcp-vertex"),
        ("azure-storge", "azure-storage"),
        ("amazon kms", "aws-kms"),
    ],
)
def test_a_provider_typed_keeps_the_suggestions_to_it_among_hundreds(
    query: str, first: str
) -> None:
    found = suggest(query, THREATMODEL_IDS)

    assert found[0] == first
    provider = first.partition("-")[0]
    assert {key.partition("-")[0] for key in found} == {provider}


def test_a_cloud_prefixed_service_still_reaches_its_threatmodel() -> None:
    # "cloud" begins a dozen Google services, so gcp-storage need not rank
    # first. It has to be among the suggestions, with no other provider's
    # beside it.
    found = suggest("gcp-cloudstorage", THREATMODEL_IDS)

    assert "gcp-storage" in found
    assert {key.partition("-")[0] for key in found} == {"gcp"}


def test_a_service_of_another_provider_is_kept_when_the_typed_one_has_none() -> None:
    # Nothing of AWS is close to "bigquery", so the typed provider is a slip
    # and the service is the better clue.
    assert suggest("aws-bigquery", KEYS)[0] == "gcp-bigquery"
    assert suggest("aws-bigquery", THREATMODEL_IDS)[0] == "gcp-bigquery"
    assert suggest("gcp-storage", KEYS)[0] == "azure-storage"


def test_a_provider_with_only_a_look_alike_does_not_hide_the_service() -> None:
    # Every key of a provider shares its prefix with the query, so a key that is
    # alike only by that prefix says nothing about what was meant.
    readable = ["aws-bedrock", "gcp-bigquery"]

    assert suggest("aws-bigquery", readable)[0] == "gcp-bigquery"


@pytest.mark.parametrize("limit", [1, 2, 3, 5])
@pytest.mark.parametrize(
    "query",
    ["ec3", "aws-ec3", "aws-iam", "s", "sq", "storage", "vertex", "Gemini", "gke"],
)
def test_suggestions_stay_within_the_limit_unique_and_among_the_candidates(
    query: str, limit: int
) -> None:
    found = suggest(query, KEYS, limit=limit)

    assert len(found) <= limit
    assert len(found) == len(set(found))
    assert set(found) <= set(KEYS)


def test_only_candidates_are_ever_suggested() -> None:
    # Two packs the caller can read: whatever an alias or a near spelling says,
    # nothing else may be named.
    readable = ["aws-s3", "gcp-bigquery"]

    for query in ["ec3", "vertex ai", "aws-ec3", "s4", "keyvault", "big query"]:
        assert set(suggest(query, readable)) <= set(readable)


@pytest.mark.parametrize(
    ("suggestions", "expected"),
    [
        ([], ""),
        (["aws-ec2"], "Did you mean aws-ec2?"),
        (["aws-ec2", "aws-s3"], "Did you mean aws-ec2 or aws-s3?"),
        (
            ["aws-ec2", "aws-s3", "aws-eks"],
            "Did you mean aws-ec2, aws-s3 or aws-eks?",
        ),
    ],
)
def test_suggestions_read_as_one_sentence(
    suggestions: list[str], expected: str
) -> None:
    assert did_you_mean(suggestions) == expected


def test_a_known_title_follows_its_key() -> None:
    labels = {"gcp-vertex": "Vertex AI", "aws-s3": ""}

    assert (
        did_you_mean(["gcp-vertex"], labels) == "Did you mean gcp-vertex (Vertex AI)?"
    )
    # A key without a title, or with an empty one, is named alone.
    assert did_you_mean(["aws-ec2", "aws-s3", "gcp-vertex"], labels) == (
        "Did you mean aws-ec2, aws-s3 or gcp-vertex (Vertex AI)?"
    )


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("gpc", ["gcp"]),
        ("azr", ["azure"]),
        ("asw", ["aws"]),
        ("Google", ["gcp"]),
        ("amazon", ["aws"]),
        ("gcp", []),
        ("oracle", []),
    ],
)
def test_a_near_provider_is_suggested(query: str, expected: list[str]) -> None:
    assert suggest_provider(query) == expected

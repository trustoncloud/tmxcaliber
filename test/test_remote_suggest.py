"""Telling someone which pack or ThreatModel a mistyped name probably meant."""

from __future__ import annotations

import pathlib
import re
from types import MappingProxyType
from typing import NamedTuple

import pytest

from tmxcaliber.lib.remote import suggest as suggest_module
from tmxcaliber.lib.remote.suggest import (
    ALIASES,
    alternative_names,
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


class ThreatModelRow(NamedTuple):
    """One row of ``threatmodels list``, as far as a suggestion reads it."""

    tm_id: str
    title: str
    covered: tuple[str, ...]


#: Every ThreatModel the catalogue published when this was written, which is the
#: list the ``threatmodels`` commands suggest from. It is a far larger and more
#: crowded set than the packs, and the same name can exist under several
#: providers, so it shows what the short pack list cannot. Each line holds the
#: id, the title and the other services it covers, separated by tabs, with the
#: covered services separated by bars.
THREATMODELS: tuple[ThreatModelRow, ...] = tuple(
    ThreatModelRow(tm_id, title, tuple(filter(None, covered.split("|"))))
    for tm_id, title, covered in (
        line.split("\t")
        for line in pathlib.Path(__file__)
        .with_name("threatmodels.tsv")
        .read_text(encoding="utf-8")
        .splitlines()
    )
)

THREATMODEL_IDS: tuple[str, ...] = tuple(row.tm_id for row in THREATMODELS)

#: The names each ThreatModel is also written as, from the title it was
#: published under and the services it covers, as the command line reads them
#: from the same list rows.
THREATMODEL_NAMES: dict[str, tuple[str, ...]] = {
    row.tm_id: alternative_names(row.title, *row.covered) for row in THREATMODELS
}

#: The same, from the title alone. The contract's list row carries a title but
#: no covered services, so this is what the command line reads today, and the
#: covered services of `THREATMODEL_NAMES` are what it would add if a row did.
THREATMODEL_TITLES: dict[str, tuple[str, ...]] = {
    row.tm_id: alternative_names(row.title) for row in THREATMODELS
}

#: Runs a test once for each way the list can publish names.
PUBLISHED_AS = pytest.mark.parametrize(
    "names",
    [THREATMODEL_TITLES, THREATMODEL_NAMES],
    ids=["titles", "titles-and-covered"],
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


@pytest.mark.parametrize(
    ("query", "first"),
    [
        ("aws-kms", "gcp-cloudkms"),
        ("AWS KMS", "gcp-cloudkms"),
        ("aws kms", "gcp-cloudkms"),
        ("Amazon KMS", "gcp-cloudkms"),
    ],
)
def test_a_weak_look_alike_of_the_typed_provider_does_not_hide_an_exact_alias(
    query: str, first: str
) -> None:
    # No pack of AWS is a KMS, and aws-eks is only spelled a little like "kms"
    # (0.67), so it names nothing. Google's Cloud KMS is the one pack that the
    # alias "kms" names, and dropping it would leave only wrong suggestions.
    found = suggest(query, KEYS)

    assert found[0] == first
    assert "aws-eks" not in found[:1]


@pytest.mark.parametrize(
    ("query", "named"),
    [
        ("azure-ebs", "aws-ec2"),
        ("aws-cloud-sql", "gcp-cloudsql"),
        ("azure-secrets-manager", "aws-secretsmanager"),
        ("aws-sql-database", "azure-sql"),
    ],
)
def test_an_exact_alias_of_another_provider_survives_among_hundreds(
    query: str, named: str
) -> None:
    # The same slip with the whole catalogue to look in: many keys of the typed
    # provider are a little like the service, and none of them is the service.
    assert suggest(query, THREATMODEL_IDS)[0] == named


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        # A service of the typed provider that is spelled like the alias, not
        # just a little like the query, is a real match, and the typed provider
        # stays with it.
        ("amazon kms", "aws"),
        ("aws-iamm", "aws"),
        ("gcp-storge", "gcp"),
    ],
)
def test_a_close_service_of_the_typed_provider_still_keeps_the_provider(
    query: str, expected: str
) -> None:
    found = suggest(query, THREATMODEL_IDS)

    assert {key.partition("-")[0] for key in found} == {expected}


@pytest.mark.parametrize(
    ("titles", "expected"),
    [
        (
            ("AWS Key Management Service (AWS KMS)",),
            (
                "AWS Key Management Service (AWS KMS)",
                "AWS Key Management Service",
                "AWS KMS",
            ),
        ),
        (("Azure Kubernetes Service",), ("Azure Kubernetes Service",)),
        (
            ("Amazon Keyspaces (for Apache Cassandra)",),
            (
                "Amazon Keyspaces (for Apache Cassandra)",
                "Amazon Keyspaces",
                "for Apache Cassandra",
            ),
        ),
        (
            ("Amazon EC2", "Amazon Elastic Block Store (Amazon EBS)"),
            (
                "Amazon EC2",
                "Amazon Elastic Block Store (Amazon EBS)",
                "Amazon Elastic Block Store",
                "Amazon EBS",
            ),
        ),
        (("  ", "Same", "Same"), ("Same",)),
        ((), ()),
    ],
)
def test_a_title_is_also_written_without_its_brackets_and_by_what_they_hold(
    titles: tuple[str, ...], expected: tuple[str, ...]
) -> None:
    assert alternative_names(*titles) == expected


@PUBLISHED_AS
def test_every_threatmodel_is_reached_by_the_title_it_was_published_under(
    names: dict[str, tuple[str, ...]],
) -> None:
    # The list rows say what each ThreatModel is called, so its own title typed
    # back has to lead to it, and not to a stranger's, whatever the provider.
    missed = {
        row.title: found[:3]
        for row in THREATMODELS
        if (found := suggest(row.title, THREATMODEL_IDS, extra_aliases=names))[:1]
        != [row.tm_id]
    }

    assert missed == {}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Azure Kubernetes Service", "azure-aks"),
        ("AWS Key Management Service", "aws-kms"),
        ("AWS Key Management Service (AWS KMS)", "aws-kms"),
        ("aws-keymanagementservice", "aws-kms"),
        ("AWS Certificate Manager (ACM)", "aws-acm"),
        ("AWS Certificate Manager", "aws-acm"),
        ("AWS ACM", "aws-acm"),
        ("AWS Identity and Access Management (IAM)", "aws-iam"),
        ("Amazon Elastic Kubernetes Service", "aws-eks"),
        ("Google Kubernetes Engine (GKE)", "gcp-gke"),
        # A service a ThreatModel also covers is named in its own words.
        ("IAM Access Analyzer", "aws-iam"),
        ("Amazon Elastic Block Store (Amazon EBS)", "aws-ec2"),
        ("AWS PrivateLink", "aws-vpc"),
        # The short form in brackets, which no spelling of the service reaches.
        ("Amazon MSK", "aws-kafka"),
        ("MSK Serverless", "aws-kafka"),
        ("Amazon Managed Streaming for Apache Kafka", "aws-kafka"),
        ("AWS STS", "aws-iam"),
        ("Amazon DocumentDB", "aws-rds"),
    ],
)
def test_a_name_the_list_publishes_leads_to_its_threatmodel_first(
    query: str, expected: str
) -> None:
    found = suggest(query, THREATMODEL_IDS, extra_aliases=THREATMODEL_NAMES)

    assert found[0] == expected
    # The typed AWS is a clue too, so no other provider's ThreatModel follows.
    provider = query.split()[0].lower()
    if provider in ("aws", "azure"):
        assert {key.partition("-")[0] for key in found} == {provider}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Azure Kubernetes Service", ["azure-aks"]),
        ("AWS Key Management Service (AWS KMS)", ["aws-kms"]),
        ("Amazon Elastic Block Store (Amazon EBS)", ["aws-ec2"]),
        # Typed the way the list publishes it, so there is no slip to correct
        # and the look-alikes that would follow are left out.
        ("Gemini Enterprise", ["gcp-discoveryengine"]),
    ],
)
def test_a_name_the_list_publishes_exactly_is_not_followed_by_look_alikes(
    query: str, expected: list[str]
) -> None:
    assert suggest(query, THREATMODEL_IDS, extra_aliases=THREATMODEL_NAMES) == expected


def test_a_title_two_providers_share_leads_to_both() -> None:
    # "API Gateway" is Google's own title and the title of AWS's with its
    # bracket cut, and only the typed provider can tell them apart.
    found = suggest("API Gateway", THREATMODEL_IDS, extra_aliases=THREATMODEL_NAMES)

    assert found == ["gcp-apigateway", "aws-apigatewayv2"]
    assert suggest(
        "Amazon API Gateway", THREATMODEL_IDS, extra_aliases=THREATMODEL_NAMES
    ) == ["aws-apigatewayv2"]


def test_an_official_name_beats_an_alias_that_leads_to_another_provider() -> None:
    # The alias "key management service" names Google's, and AWS's official name
    # for its own service is the same words with AWS in front.
    plain = suggest("AWS Key Management Service", THREATMODEL_IDS)
    named = suggest(
        "AWS Key Management Service", THREATMODEL_IDS, extra_aliases=THREATMODEL_NAMES
    )

    assert plain[0] == "gcp-cloudkms"
    assert named == ["aws-kms"]


def test_names_are_only_ever_taken_for_candidates() -> None:
    # A name from a row the caller did not list leads nowhere, as an alias to
    # a pack outside the list does not.
    readable = [key for key in THREATMODEL_IDS if key != "aws-kms"]

    found = suggest(
        "AWS Key Management Service", readable, extra_aliases=THREATMODEL_NAMES
    )

    assert "aws-kms" not in found
    assert set(found) <= set(readable)


def test_names_given_for_the_call_are_added_to_the_aliases_and_replace_none() -> None:
    # "kms" is an alias of gcp-cloudkms and a name of aws-kms, and both are
    # right until the typed provider says which.
    found = suggest("KMS", THREATMODEL_IDS, extra_aliases=THREATMODEL_NAMES)

    assert {"gcp-cloudkms", "aws-kms"} <= set(found[:2])
    assert suggest("Gemini Agent Platform", THREATMODEL_IDS, extra_aliases={}) == [
        "gcp-vertex"
    ]


def test_a_slip_of_a_key_is_not_outranked_by_a_near_miss_title() -> None:
    # "firestor" is a slip of Firestore, and a near miss (0.82) of the other
    # ThreatModel's title, Filestore. The key is the closer of the two (0.95), so
    # the published title must weigh in beside the key, not above it.
    readable = ["gcp-filestore", "gcp-firestore", "gcp-firebase"]
    names = {
        "gcp-filestore": ("Filestore",),
        "gcp-firestore": ("Cloud Firestore",),
        "gcp-firebase": ("Firebase",),
    }

    assert suggest("gcp-firestor", readable, extra_aliases=names)[0] == "gcp-firestore"
    assert suggest("gcp-firestor", readable)[0] == "gcp-firestore"


def test_a_service_typed_exactly_is_not_outranked_by_a_close_title() -> None:
    readable = ["gcp-filestore", "gcp-firestore", "gcp-firebase"]
    names = {
        "gcp-filestore": ("Filestore",),
        "gcp-firestore": ("Cloud Firestore",),
        "gcp-firebase": ("Firebase",),
    }

    assert suggest("Firestore", readable, extra_aliases=names)[0] == "gcp-firestore"


def test_a_service_typed_exactly_is_kept_beside_a_title_of_the_same_word() -> None:
    # Azure's title is exactly "Compute" once its vendor is cut, and Google's
    # service is exactly "compute". Each is an exact match, and the one that
    # is named by the title must not push out the one named by the key.
    readable = ["azure-compute", "gcp-compute", "gcp-composer"]
    names = {"azure-compute": ("Azure Compute",), "gcp-compute": ("Compute Engine",)}

    assert suggest("Compute", readable, extra_aliases=names) == [
        "azure-compute",
        "gcp-compute",
    ]


def test_titles_that_begin_with_the_typed_word_do_not_outrank_the_service() -> None:
    # Three titles begin with "network", and together they would fill the
    # limit before the one ThreatModel whose service is "network".
    readable = [
        "aws-networkmanager",
        "aws-networkfirewall",
        "gcp-networksecurity",
        "azure-network",
    ]
    names = {
        "aws-networkmanager": ("AWS Network Manager",),
        "aws-networkfirewall": ("AWS Network Firewall",),
        "gcp-networksecurity": ("Network Security",),
        "azure-network": ("Azure Virtual Network",),
    }

    assert suggest("Network", readable, extra_aliases=names)[0] == "azure-network"


def test_a_close_near_miss_title_outranks_a_loosely_close_key() -> None:
    # The title is a near miss of the query at 0.96, and the other key's service
    # only at 0.77. A title counts at the ratio it scores, so it is the nearer
    # of the two and leads. At a flat 0.75 it would come second.
    readable = ["gcp-ocelot", "gcp-zebra-crosxyz"]
    names = {"gcp-ocelot": ("Zebra Crossing",)}

    assert suggest("Zebra Crossin", readable, extra_aliases=names)[0] == "gcp-ocelot"
    assert suggest("Zebra Crossin", readable) == ["gcp-zebra-crosxyz"]


def test_a_title_that_begins_with_the_typed_words_still_leads_to_its_key() -> None:
    readable = ["aws-kafka", "aws-eks"]
    names = {"aws-kafka": ("Amazon Managed Streaming for Apache Kafka",)}

    assert suggest("Managed Streaming", readable) == []
    assert suggest("Managed Streaming", readable, extra_aliases=names) == ["aws-kafka"]


def test_a_service_typed_exactly_is_not_hidden_by_a_provider_look_alike() -> None:
    # "aws-compute" names no AWS ThreatModel. aws-computeoptimizer is spelled a
    # little like it (0.61), which says nothing about what was meant, while two
    # other providers have a service called exactly "compute".
    readable = ["aws-computeoptimizer", "azure-compute", "gcp-compute"]

    assert suggest("aws-compute", readable)[:2] == ["azure-compute", "gcp-compute"]


@PUBLISHED_AS
def test_a_service_typed_exactly_is_followed_by_the_titles_that_begin_with_it(
    names: dict[str, tuple[str, ...]],
) -> None:
    # Dataproc is not a title, so no name is exact and what begins with the word
    # still follows the one ThreatModel whose service it is.
    found = suggest("Dataproc", THREATMODEL_IDS, extra_aliases=names)

    assert found[:2] == ["gcp-dataproc", "gcp-metastore"]


@PUBLISHED_AS
def test_a_name_that_is_an_alias_is_not_cut_short_by_a_title(
    names: dict[str, tuple[str, ...]],
) -> None:
    # "vertex" is an alias of gcp-vertex and the first word of Vertex AI
    # Workbench's title. Typed as the alias it names the one pack, as "ec2" does
    # not also lead to "ec2 auto scaling".
    assert suggest("vertex", THREATMODEL_IDS, extra_aliases=names) == ["gcp-vertex"]


@PUBLISHED_AS
@pytest.mark.parametrize("provider", ["aws", "gcp"])
def test_a_typed_provider_whose_titles_begin_with_a_service_keeps_the_provider(
    names: dict[str, tuple[str, ...]], provider: str
) -> None:
    # Azure's service is exactly "network", and a title of each other provider
    # begins with that word. Typing either of them names the provider as well,
    # and a title of its own is a firm answer to Azure's exact service.
    found = suggest(f"{provider}-network", THREATMODEL_IDS, extra_aliases=names)

    assert found
    assert {key.partition("-")[0] for key in found} == {provider}


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        # The first words of a title, which no spelling of the key reaches.
        ("Managed Streaming", "aws-kafka"),
        ("Azure Kubernetes", "azure-aks"),
        # A title typed with a slip.
        ("Amazon Managed Streaming for Apache Kafk", "aws-kafka"),
        ("Azure Kubernetes Servce", "azure-aks"),
    ],
)
def test_a_title_cut_short_or_slipped_still_leads_to_its_threatmodel(
    names: dict[str, tuple[str, ...]], query: str, expected: str
) -> None:
    assert suggest(query, THREATMODEL_IDS, extra_aliases=names)[0] == expected


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("gcp-firestor", "gcp-firestore"),
        ("gcp-firesore", "gcp-firestore"),
        ("aws-qconnet", "aws-qconnect"),
        ("aws-qconect", "aws-qconnect"),
        ("gcp-dataporc", "gcp-dataproc"),
        ("aws-acmpc", "aws-acmpca"),
        ("gcp-cloudasst", "gcp-cloudasset"),
    ],
)
def test_a_slip_of_a_threatmodels_id_still_leads_to_it_among_the_titles(
    names: dict[str, tuple[str, ...]], query: str, expected: str
) -> None:
    # Another ThreatModel's title is a near miss of each of these slips
    # (Filestore, Connect, Dataform, ACM), and none may lead the real one.
    found = suggest(query, THREATMODEL_IDS, extra_aliases=names)

    assert found[0] == expected


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Firestore", "gcp-firestore"),
        ("Dataproc", "gcp-dataproc"),
        ("Redis", "gcp-redis"),
        ("Events", "aws-events"),
        ("Monitoring", "gcp-monitoring"),
        ("Network", "azure-network"),
    ],
)
def test_a_service_typed_exactly_leads_to_its_threatmodel_among_the_titles(
    names: dict[str, tuple[str, ...]], query: str, expected: str
) -> None:
    # Each is a ThreatModel's own service. Among the 269, other titles hold the
    # same word, or one a letter away, and none of them is what was typed.
    found = suggest(query, THREATMODEL_IDS, extra_aliases=names)

    assert found[0] == expected


@PUBLISHED_AS
def test_a_service_two_providers_share_leads_to_both_among_the_titles(
    names: dict[str, tuple[str, ...]],
) -> None:
    # Azure and Google both have a Compute, and the title that is exactly
    # "Compute" is Azure's. Google's must not be dropped for it.
    found = suggest("Compute", THREATMODEL_IDS, extra_aliases=names)

    assert found == ["azure-compute", "gcp-compute"]


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        # A slip of a ThreatModel's own title, where a curated alias nearly
        # names another ThreatModel: "secrets manager" is AWS's, "storage" is
        # Azure's, "gemini enterprise agent platform" is Vertex AI's.
        ("Secret Manger", "gcp-secretmanager"),
        ("Clod Storage", "gcp-storage"),
        ("Gemini Enterprse", "gcp-discoveryengine"),
        ("AWS Sytems Manager", "aws-ssm"),
        ("Azur Kubernetes Service", "azure-aks"),
        ("AWS Tranform", "aws-transform"),
        ("Cloud Taks", "gcp-cloudtasks"),
        # The first words of a title, where a curated alias begins with a word
        # a letter away.
        ("AWS Systems", "aws-ssm"),
    ],
)
def test_a_slip_of_a_published_title_leads_to_its_own_threatmodel(
    names: dict[str, tuple[str, ...]], query: str, expected: str
) -> None:
    # The list says what each ThreatModel is called, and a curated alias is only
    # a guess at what a pack is called, so the title typed with a slip leads.
    assert suggest(query, THREATMODEL_IDS, extra_aliases=names)[0] == expected


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("Azure AI", {"azure-botservice", "azure-cognitiveservices", "azure-search"}),
        ("AWS Cost", {"aws-ce", "aws-costoptimizationhub"}),
    ],
)
def test_the_first_words_of_several_titles_lead_to_each_of_them(
    names: dict[str, tuple[str, ...]], query: str, expected: set[str]
) -> None:
    # Each title begins with the words typed, and a ThreatModel whose service is
    # only spelled a little like the last word must not come before them.
    found = suggest(query, THREATMODEL_IDS, extra_aliases=names)

    assert set(found[: len(expected)]) == expected


def test_a_near_miss_of_a_title_waits_behind_a_key_spelled_nearer() -> None:
    # "Secrets Manger" is a near miss of the curated "secrets manager" (0.97),
    # of a key's service (0.96) and of the title Secret Manager (0.93). A title
    # competes with the curated names only when no key it does not lead to is
    # spelled nearer, so that key keeps its place ahead of the title.
    readable = ["aws-secretsmanager", "gcp-secretmanager", "gcp-secretsmanger"]
    names = {"gcp-secretmanager": ("Secret Manager",)}

    assert suggest("Secrets Manger", readable, extra_aliases=names) == [
        "aws-secretsmanager",
        "gcp-secretsmanger",
        "gcp-secretmanager",
    ]
    # Typed nearer the title than anything else, the title leads.
    assert (
        suggest("Secret Manger", readable, extra_aliases=names)[0]
        == "gcp-secretmanager"
    )


def test_a_published_name_comes_before_a_curated_one_as_long() -> None:
    # "key" begins the curated alias "key vault" and the published title "Key
    # Store", both nine letters. The list says what its ThreatModel is called,
    # and the curated table only guesses, so the title leads.
    readable = ["azure-keyvault", "gcp-keystore"]
    names = {"gcp-keystore": ("Key Store",)}

    assert suggest("key", readable, extra_aliases=names) == [
        "gcp-keystore",
        "azure-keyvault",
    ]


@PUBLISHED_AS
def test_a_short_query_one_edit_from_a_service_is_not_led_away_by_a_title(
    names: dict[str, tuple[str, ...]],
) -> None:
    # "q" begins the titles of several Amazon Q ThreatModels, and "mq" is one
    # edit from it. A query this short is as likely a slip of a service as the
    # start of a title, so the service keeps its place.
    assert suggest("aws-q", THREATMODEL_IDS, extra_aliases=names)[0] == "aws-mq"


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "expected"),
    [
        # "API Gateway" is Google's title, and the title of AWS's once its
        # bracket is cut.
        ("API Gatewy", ["gcp-apigateway", "aws-apigatewayv2"]),
        # "Certificate Manager" is Google's title, and AWS's once cut.
        ("Certificate Manger", ["gcp-certificatemanager", "aws-acm"]),
    ],
)
def test_a_slip_of_a_name_two_threatmodels_publish_leads_to_its_own_title_first(
    names: dict[str, tuple[str, ...]], query: str, expected: list[str]
) -> None:
    # The name is one ThreatModel's whole title and only a cut form of the
    # other's, so the whole title comes first, as it does when typed exactly.
    found = suggest(query, THREATMODEL_IDS, extra_aliases=names)

    assert found[: len(expected)] == expected


def _single_edit_slips(tm_id: str) -> list[str]:
    """Spell a ThreatModel's id with one letter of its service missing or swapped.

    Args:
        tm_id: A published id, such as ``gcp-firestore``.

    Returns:
        Each id that drops one letter of the service, or swaps two neighbouring
        letters of it, in order, leaving out any that is another published id.
    """
    provider, _, service = tm_id.partition("-")
    slips = [f"{provider}-{service[:i]}{service[i + 1 :]}" for i in range(len(service))]
    slips += [
        f"{provider}-{service[:i]}{service[i + 1]}{service[i]}{service[i + 2 :]}"
        for i in range(len(service) - 1)
        if service[i] != service[i + 1]
    ]
    return [
        slip
        for slip in dict.fromkeys(slips)
        if slip != tm_id and slip not in THREATMODEL_IDS
    ]


def _place(found: list[str], tm_id: str) -> int:
    """Say where a suggestion list puts a ThreatModel, with a miss last.

    Args:
        found: The suggestions, best first.
        tm_id: The ThreatModel looked for.

    Returns:
        Its position, or the length of the list when it is not there.
    """
    return found.index(tm_id) if tm_id in found else len(found)


@PUBLISHED_AS
def test_publishing_titles_never_moves_a_mistyped_id_off_its_threatmodel(
    names: dict[str, tuple[str, ...]],
) -> None:
    # A title can only add evidence. Typing an id with one letter dropped or two
    # swapped must put its ThreatModel no later with the titles published than
    # without them, for every ThreatModel there is. Every eighth slip is tried
    # to keep the suite quick (all 4546 take half a minute), which still reaches
    # each ThreatModel the review found out of place, and the ones it found are
    # named in the tests above, so none of them rests on the sample.
    slips = [
        (row.tm_id, slip)
        for row in THREATMODELS
        for slip in _single_edit_slips(row.tm_id)
    ]
    worse: dict[str, tuple[int, int]] = {}
    for tm_id, slip in slips[::8]:
        named = suggest(slip, THREATMODEL_IDS, extra_aliases=names)
        if _place(named, tm_id) == 0:
            continue
        plain = suggest(slip, THREATMODEL_IDS)
        if _place(named, tm_id) > _place(plain, tm_id):
            worse[slip] = (_place(plain, tm_id), _place(named, tm_id))

    assert worse == {}


@PUBLISHED_AS
@pytest.mark.parametrize(
    ("query", "tm_id"),
    [("aws-ms", "aws-dms"), ("aws-ms", "aws-fms"), ("aws-es", "aws-eks")],
)
def test_a_near_miss_title_does_not_jump_ahead_of_a_key_spelled_as_near(
    names: dict[str, tuple[str, ...]], query: str, tm_id: str
) -> None:
    # Two letters are as near to a short title, such as the "MSK" of Amazon
    # MSK, or a short curated name, such as "kms", as to several services. A
    # title answers a curated near miss only when it is nearer than every key
    # it does not lead to, so here it waits with the keys, and the ThreatModel
    # is placed no later than with no titles at all.
    found = suggest(query, THREATMODEL_IDS, extra_aliases=names)

    assert _place(found, tm_id) <= _place(suggest(query, THREATMODEL_IDS), tm_id)


def _title_slips(title: str) -> list[str]:
    """Spell a title with one letter missing or two neighbouring letters swapped.

    Args:
        title: A published title, such as ``Secret Manager``.

    Returns:
        Each spelling that drops one letter or digit, or swaps two neighbouring
        ones that differ, sorted, leaving out any that is a published name.
    """
    slips = {
        title[:i] + title[i + 1 :] for i in range(len(title)) if title[i].isalnum()
    }
    slips |= {
        title[:i] + title[i + 1] + title[i] + title[i + 2 :]
        for i in range(len(title) - 1)
        if title[i].isalnum() and title[i + 1].isalnum() and title[i] != title[i + 1]
    }
    published = {
        normalize(name) for names in THREATMODEL_TITLES.values() for name in names
    }
    return sorted(slip for slip in slips if normalize(slip) not in published)


def test_the_curated_names_never_move_a_mistyped_title_off_its_threatmodel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The curated table is a guess at what packs are called, and the list says
    # what each ThreatModel is called. Typing a title with a slip must put its
    # ThreatModel no later with the curated table than with an empty one. Every
    # sixteenth slip is tried to keep the suite quick (all 8584 take a minute),
    # which still reaches the titles round 4 found out of place, and the ones it
    # named are pinned by the tests above.
    slips = [
        (row.tm_id, slip) for row in THREATMODELS for slip in _title_slips(row.title)
    ]
    # Only a slip whose ThreatModel is not first can be placed later, so the
    # empty table is asked about those alone.
    behind = [
        (tm_id, slip, found)
        for tm_id, slip in slips[::16]
        if _place(
            found := suggest(slip, THREATMODEL_IDS, extra_aliases=THREATMODEL_TITLES),
            tm_id,
        )
        > 0
    ]
    monkeypatch.setattr(suggest_module, "ALIASES", MappingProxyType({}))
    worse = {
        slip: (found, plain)
        for tm_id, slip, found in behind
        if _place(found, tm_id)
        > _place(
            plain := suggest(slip, THREATMODEL_IDS, extra_aliases=THREATMODEL_TITLES),
            tm_id,
        )
    }

    assert worse == {}


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

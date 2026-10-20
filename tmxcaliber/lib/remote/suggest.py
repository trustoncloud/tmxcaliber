"""Tell someone which pack or ThreatModel a mistyped or renamed name meant.

A name is typed from memory, so ``ec3`` for ``aws-ec2``, ``bigqeury`` for
``gcp-bigquery``, or a product's new name, such as Gemini Agent Platform for
what the ThreatModel and the pack still call ``gcp-vertex``, would otherwise
end in a bare "not found". Everything here is a pure function over names the
caller passes in, so the caller decides which names may be suggested.

**Only candidates are ever suggested.** The caller passes the names its key can
list, and a name outside them would tell the reader about a pack or a
ThreatModel their subscription does not cover. An alias that leads to such a
name therefore contributes nothing.
"""

from __future__ import annotations

import re
from collections.abc import Container, Iterable, Mapping, Sequence
from difflib import SequenceMatcher
from types import MappingProxyType
from typing import Final

#: The provider each word that names a vendor stands for, as release keys spell
#: the provider. Such a word names a vendor, never a service, so a leading one
#: is dropped when it stands as its own word and ``Amazon EC2``, ``AWS EC2`` and
#: ``ec2`` read alike, while ``gcp`` inside ``gcpvertex`` is left alone. It also
#: tells which provider a person meant, which an alias for another provider's
#: service must not override.
_PROVIDER_OF: Final[Mapping[str, str]] = MappingProxyType(
    {
        "amazon": "aws",
        "aws": "aws",
        "google": "gcp",
        "gcp": "gcp",
        "azure": "azure",
        "microsoft": "azure",
    }
)

#: The words that name a vendor, which `normalize` drops from the front of a name.
_VENDORS: Final[frozenset[str]] = frozenset(_PROVIDER_OF)

#: A run of anything other than a lowercase letter or a digit. Spaces,
#: underscores and slashes are the separators people type, and treating every
#: other mark the same way lets ``Elastic Compute Cloud (EC2)`` reach an alias
#: as well.
_SEPARATORS: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

#: A bracketed part of a title, such as the ``(AWS KMS)`` of ``AWS Key
#: Management Service (AWS KMS)``.
_BRACKETED: Final[re.Pattern[str]] = re.compile(r"\(([^()]*)\)")

#: How close an alias has to be to count as a slip of the keys. Alias names are
#: phrases of several words, so a query that shares one long word with one
#: scores well above difflib's usual 0.6 while naming nothing:
#: ``kubernetesx-zzz`` scores 0.69 against ``kubernetes-engine``. A letter or
#: two out of place, as in ``vertexai`` (0.94) or ``keyvalt`` (0.88), stays
#: well above this.
_ALIAS_CUTOFF: Final[float] = 0.75

#: How close a key's service has to be, which is difflib's own default. A
#: service is a short single word, so a near miss there is far less likely to
#: be a shared word that names nothing. The provider before it is left out of
#: the comparison, because every key of a provider shares it: compared whole,
#: ``aws-ec3`` scores 0.77 against ``aws-s3`` on the prefix alone.
_KEY_CUTOFF: Final[float] = 0.6

#: The longest query whose one-edit neighbours are suggested whatever their
#: ratio. A short name scores low on a ratio even when one key was hit wrong,
#: as ``s4`` scores 0.5 against ``s3``, while one edit of a longer name scores
#: at least what one letter hit wrong does, which clears `_KEY_CUTOFF`.
_SHORT: Final[int] = 4

#: The providers a pack or a ThreatModel belongs to, as release keys spell them.
PROVIDERS: Final[tuple[str, ...]] = ("aws", "azure", "gcp")

#: Other names for each pack, by its release key, as people write them.
#:
#: Collected from three places: the display names in ccr_factory's
#: ``services.json``, the ``service_name`` and ``other_covered_services`` of
#: each ThreatModel, and the user's note that Google renamed Vertex AI to
#: Gemini Agent Platform while the ThreatModel and the pack keep the key
#: ``gcp-vertex``. It is a starting set. The names belong to the ThreatModel
#: team, which should eventually publish them as metadata so this table can be
#: read instead of kept by hand.
#:
#: The gcp-vertex ThreatModel spells one of its products "Collab Enterprise",
#: and Google spells it "Colab Enterprise". Both are listed, so each is an exact
#: name and neither relies on being a near miss of the other.
#:
#: A name that people shorten to a word, such as ``kms`` or ``gemini``, is
#: listed as that word. Spelling rules cannot reach it from the full name.
_NAMES: Final[Mapping[str, tuple[str, ...]]] = {
    "aws-s3": ("s3", "simple storage service"),
    "aws-ec2": ("ec2", "elastic compute cloud", "elastic block store", "ebs"),
    "aws-autoscaling": ("auto scaling", "ec2 auto scaling", "autoscaling"),
    "aws-transfer": ("transfer family", "transfer"),
    "aws-eks": ("eks", "elastic kubernetes service"),
    "aws-bedrock": ("bedrock",),
    "aws-bedrockagentcore": ("agentcore", "agent core", "bedrock agentcore"),
    "aws-secretsmanager": ("secrets manager",),
    "azure-storage": ("storage", "storage account", "blob storage"),
    "azure-keyvault": ("key vault",),
    "azure-sql": ("sql database",),
    "gcp-bigquery": ("bigquery", "big query"),
    "gcp-pubsub": ("pub sub", "pubsub"),
    "gcp-vertex": (
        "vertex",
        "vertex ai",
        "gemini agent platform",
        "gemini enterprise agent platform",
        "gemini",
        "gemini enterprise",
        "collab enterprise",
        "colab enterprise",
    ),
    "gcp-notebooks": ("vertex ai workbench", "workbench", "notebooks"),
    "gcp-gke": ("gke", "kubernetes engine", "google kubernetes engine"),
    "gcp-cloudsql": ("cloud sql",),
    "gcp-cloudkms": ("cloud kms", "kms", "key management service"),
    "gcp-iam": ("iam",),
    "gcp-compute": ("compute engine", "gce"),
}

#: Other names for each provider, written as `_canonical` leaves them. The
#: vendor's own name is the alias here, so it is not dropped as it is from a
#: service's name.
_PROVIDER_NAMES: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "amazon": ("aws",),
        "amazon-web-services": ("aws",),
        "google": ("gcp",),
        "google-cloud": ("gcp",),
        "google-cloud-platform": ("gcp",),
        "microsoft": ("azure",),
        "microsoft-azure": ("azure",),
    }
)


def _canonical(name: str) -> str:
    """Spell a name the one way keys are spelled, keeping every word.

    Args:
        name: The name as typed.

    Returns:
        The name in lowercase, with each run of separators turned into one
        hyphen and none at either end.
    """
    return _SEPARATORS.sub("-", name.strip().lower()).strip("-")


def normalize(name: str) -> str:
    """Spell a name the way aliases are stored, without its vendor.

    A full key such as ``aws-ec2`` comes out as its service, ``ec2``, so it
    meets an alias written without a vendor. `suggest` reads the provider from
    the query separately, to narrow and order by it, so it is not lost.

    Args:
        name: The name as typed, such as ``Amazon EC2`` or ``pub/sub``.

    Returns:
        The name in lowercase, with spaces, underscores, slashes and other
        separators turned into single hyphens, and each leading vendor word
        (`_VENDORS`) dropped while another word follows it.
    """
    words = _canonical(name).split("-")
    while len(words) > 1 and words[0] in _VENDORS:
        words.pop(0)
    return "-".join(words)


def _by_name(names: Mapping[str, Iterable[str]]) -> Mapping[str, tuple[str, ...]]:
    """Turn a table of names by key into a table of keys by normalized name.

    Args:
        names: Each release key, and the names people use for it, the best
            known first.

    Returns:
        Each normalized name, and the keys it can mean, read-only. Two
        spellings that normalize alike, such as ``kubernetes engine`` and
        ``google kubernetes engine``, share one entry. A name with no letter
        or digit in it names nothing and is left out.

        Names are taken by position across all the keys, so a key's first name
        comes before any key's second. A ThreatModel's own title, which
        `alternative_names` lists first, then outranks another's title with its
        bracket cut off, as ``API Gateway`` outranks ``Amazon API Gateway (HTTP
        APIs and WebSockets)``, which reads the same once cut.
    """
    ordered = {key: tuple(alternatives) for key, alternatives in names.items()}
    table: dict[str, tuple[str, ...]] = {}
    for position in range(max(map(len, ordered.values()), default=0)):
        for key, alternatives in ordered.items():
            if position >= len(alternatives):
                continue
            normal = normalize(alternatives[position])
            if not normal:
                continue
            keys = table.get(normal, ())
            if key not in keys:
                table[normal] = (*keys, key)
    return MappingProxyType(table)


#: Each normalized alternative name, and the release keys it can mean.
ALIASES: Final[Mapping[str, tuple[str, ...]]] = _by_name(_NAMES)


def alternative_names(*titles: str) -> tuple[str, ...]:
    """List the ways a service's published titles are also written.

    A title carries its own short form in brackets, as in ``AWS Key Management
    Service (AWS KMS)``, and people type the long name, the short one, or the
    long one without the bracket. The services a ThreatModel also covers are
    named the same way.

    Args:
        *titles: A ThreatModel's title and the titles of the other services it
            covers, as the list publishes them.

    Returns:
        For each title, the title as given, then the title with each bracketed
        part left out, then each bracketed part on its own. Each appears once,
        and a blank name is left out.
    """
    names: list[str] = []
    for title in titles:
        outside = " ".join(_BRACKETED.sub(" ", title).split())
        names += [
            title.strip(),
            outside,
            *(m.strip() for m in _BRACKETED.findall(title)),
        ]
    return tuple(dict.fromkeys(name for name in names if name))


def _service(key: str) -> str:
    """Take the service from a release key.

    Args:
        key: A release key, such as ``aws-ec2``, or a provider.

    Returns:
        What follows the first hyphen, as the API splits a key, or the whole
        value when it has none.
    """
    return key.partition("-")[2] or key


def _close(
    word: str, possibilities: Iterable[str], cutoff: float
) -> list[tuple[float, str]]:
    """Score the possibilities close to a word, best first.

    The measure and the order of its checks are those of
    ``difflib.get_close_matches``. The score is kept, because a key can be
    close by its service or by a name it is published under, and both lists
    have to be ranked together.

    Args:
        word: The query.
        possibilities: What it may be close to.
        cutoff: The lowest score that counts.

    Returns:
        Each possibility that scores at least ``cutoff``, with its score,
        highest first and alphabetical among equals, so the order never
        depends on the order of the input.
    """
    matcher = SequenceMatcher()
    matcher.set_seq2(word)
    scored: list[tuple[float, str]] = []
    for possibility in possibilities:
        matcher.set_seq1(possibility)
        if (
            matcher.real_quick_ratio() >= cutoff
            and matcher.quick_ratio() >= cutoff
            and matcher.ratio() >= cutoff
        ):
            scored.append((matcher.ratio(), possibility))
    return sorted(scored, key=lambda pair: (-pair[0], pair[1]))


def _within_one_edit(first: str, second: str) -> bool:
    """Decide whether one edit turns one word into the other.

    Args:
        first: One word.
        second: The other.

    Returns:
        True when the words are equal, or one character inserted, deleted or
        substituted, or two neighbouring characters swapped, makes them so.
    """
    if first == second:
        return True
    if len(first) == len(second):
        apart = [
            i for i, (a, b) in enumerate(zip(first, second, strict=True)) if a != b
        ]
        if len(apart) == 1:
            return True
        return (
            len(apart) == 2
            and apart[1] == apart[0] + 1
            and first[apart[0]] == second[apart[1]]
            and first[apart[1]] == second[apart[0]]
        )
    shorter, longer = sorted((first, second), key=len)
    if len(longer) - len(shorter) != 1:
        return False
    return any(longer[:i] + longer[i + 1 :] == shorter for i in range(len(longer)))


def _typed_provider(
    full: str, bare: str, known: Container[str]
) -> tuple[str | None, str]:
    """Tell which provider a query begins with, and what follows it.

    A key is compared with a query by its service alone, so the provider the
    query begins with is left out of the comparison too, and kept to narrow
    and order by. `normalize` drops a vendor typed as its own word. A vendor
    typed with a slip, as in ``asw-ec3`` or ``amazn ec2``, or run into the
    service, as in ``awsec2``, is no part of the service either, and names its
    provider just the same.

    Args:
        full: The query with every word kept.
        bare: The query as `normalize` leaves it.
        known: The words that name something here, such as each candidate's
            service and each word of an alias. A known word is never read as a
            vendor, so ``aks``, Azure's service and one edit from ``aws``,
            keeps its meaning.

    Returns:
        The provider, or None when the query begins with none, and the query
        without it, spelled as `normalize` spells it.
    """
    provider = _PROVIDER_OF.get(full.partition("-")[0])
    first, _, rest = bare.partition("-")
    if provider or first in known:
        return provider, bare
    for vendor in sorted(_PROVIDER_OF, key=len, reverse=True):
        if rest and _within_one_edit(first, vendor):
            return _PROVIDER_OF[vendor], normalize(rest)
        if first.startswith(vendor) and len(first) > len(vendor):
            return _PROVIDER_OF[vendor], normalize(bare[len(vendor) :])
    return None, bare


def _provider(key: str) -> str:
    """Take the provider from a release key.

    Args:
        key: A release key, such as ``aws-ec2``.

    Returns:
        What precedes the first hyphen, as the API splits a key.
    """
    return key.partition("-")[0]


def _rank(
    query: str,
    candidates: Iterable[str],
    *,
    full: str,
    bare: str,
    aliases: Mapping[str, tuple[str, ...]],
    limit: int,
    provider: str | None = None,
    published: Mapping[str, tuple[str, ...]] | None = None,
) -> list[str]:
    """Choose the candidates a query most likely meant, best first.

    Args:
        query: The name as typed.
        candidates: The names that may be suggested.
        full: The query with every word kept, to tell a candidate spelled
            another way.
        bare: The query without the provider it begins with, to compare with
            aliases, published names and each key's service. A key is never
            compared whole, because every key of a provider shares that
            provider's prefix, and a query that shares only the prefix with a
            key says nothing about which service was meant.
        aliases: Each curated alternative name, and the keys it can mean.
        limit: How many to return at most.
        provider: The provider the query begins with, if any, which is used
            only to narrow and to order.
        published: Each name the caller itself published, such as a
            ThreatModel's title, and the keys it leads to. It is kept apart
            from `aliases` because a title is evidence about one key, and a key
            spelled almost as the query is better evidence than a title that is
            only close to it. A curated alias is a different matter: it is the
            one name its pack goes by, so a near miss of it is a likely slip.

    Returns:
        Up to ``limit`` candidates, in this order:

        1. The candidates the query names exactly: those a published name or
           an alias leads to, then those whose service, or whose whole key, is
           the query. A key named by its own spelling is as sure a match as one
           named by an alias, so ``Dataproc`` leads to ``gcp-dataproc`` before
           any title that is only like it.
        2. Published names and aliases whose first words are the query's
           words, which is how a name is cut short, shortest first and a
           published name first among names as long. Only when no name is
           exact. For a short query (`_SHORT`), a published name gives way to
           a key whose service is one edit from the query, and waits for the
           last tier.
        3. Aliases it nearly names (`_ALIAS_CUTOFF`), by how near, with the
           published names that are as near as the weakest of them and nearer
           than every key they do not lead to is spelled, first on a tie.
        4. Everything else together, by the better of two scores: how close
           the key's service is (`_KEY_CUTOFF`, and at least what one letter
           hit wrong would score when it is one edit away), and how close a
           published name is, which is `_ALIAS_CUTOFF` for a name that begins
           with the query's words, as for an alias, and the ratio itself for a
           near miss. A slip of a key therefore leads to that key ahead of a
           ThreatModel whose title is a little like the slip. On a tie, a key
           of the provider the query names comes first, then a key placed by
           its spelling, then the others in the order a published name first
           reached them.
        5. For a short query (`_SHORT`), keys whose service is one edit away,
           then keys a published name one edit away leads to, then the
           published names that gave way in tier 2.

        Nothing when the query is itself a candidate, because there is nothing
        to correct. Only the candidate itself when the query spells one in
        another case or with other separators, such as ``AWS_EC2``.

        The provider a query names is used only to narrow and to order. When
        a candidate of that provider is close, only the candidates of that
        provider are returned. Otherwise the typed provider is the slip, as in
        ``aws-bigquery``, and the service decides.

        A candidate that is only a little like the service (below
        `_ALIAS_CUTOFF`) does not count as close when a name leads to another
        provider's key exactly, or another provider's service is the query.
        ``aws-kms`` names no AWS pack, but ``aws-eks`` scores 0.67 against
        ``kms``, and counting it would drop Google's Cloud KMS, the one pack the
        alias names, and leave only wrong suggestions.

        A query that is exactly a name the caller published is no slip of the
        keys, so what follows the candidates that name leads to would only be
        noise, and they alone are returned, with any candidate whose service is
        the query, because a service typed exactly is as much its own name as a
        title is: ``Compute`` is Azure's title and Google's service.
    """
    pool = list(dict.fromkeys(candidates))
    if limit < 1 or not bare or query in pool:
        return []
    allowed = set(pool)
    if full in allowed:
        # The query is that candidate spelled another way, and beside the key
        # it plainly names any other would only be noise.
        return [full]
    titles = published or {}
    found: list[str] = []
    # The keys found by an alias, by a name the caller published, or by a
    # service spelled as close as an alias has to be. Only these can outweigh a
    # name that leads to another provider's key exactly.
    firm: set[str] = set()

    def take(keys: Iterable[str], *, firmly: bool = False) -> None:
        for key in keys:
            if key not in allowed:
                continue
            if firmly:
                firm.add(key)
            if key not in found:
                found.append(key)

    named = [key for key in titles.get(bare, ()) if key in allowed]
    aliased = [key for key in aliases.get(bare, ()) if key in allowed]
    # A service is typed as it is spelled, and a key spelled as the query is as
    # exact a hit as an alias that says so. Sorted, so the order never depends
    # on the order the caller listed the candidates in.
    spelled = sorted(key for key in pool if bare in (key, _service(key)))
    exact = list(dict.fromkeys((*named, *aliased, *spelled)))
    take(exact, firmly=True)

    # How close each key's service is spelled to the query. The tiers of names
    # below are weighed against it as well, so it is worked out first.
    by_service: dict[str, list[str]] = {}
    for key in pool:
        by_service.setdefault(_service(key), []).append(key)
    spelling = {
        key: score
        for score, name in _close(bare, by_service, _KEY_CUTOFF)
        for key in by_service[name]
    }
    # Two neighbouring letters swapped are one slip, as one letter hit wrong
    # is, and difflib can score them far lower: "kfaka" is 0.4 against
    # "kafka", where "kafkx" is 0.8. A service one edit away therefore scores
    # at least what one letter hit wrong would.
    near = {key for key in pool if _within_one_edit(bare, _service(key))}
    for key in near:
        longest = max(len(bare), len(_service(key)))
        floor = (longest - 1) / longest
        if floor >= _KEY_CUTOFF:
            spelling[key] = max(spelling.get(key, 0.0), floor)

    # The published names that begin with the query's words. A name that is
    # already an alias or a published name is not cut short, so ``ec2`` does
    # not also lead to ``ec2 auto scaling``.
    beginning = (
        sorted(
            (name for name in titles if name.startswith(f"{bare}-")),
            key=lambda name: (len(name), name),
        )
        if not (named or aliased)
        else []
    )
    # A query this short is as likely a slip of a service as the first word of
    # a title, so such a title gives way to a service one edit from it, and is
    # suggested after it: "aws-q" begins the titles of Amazon Q and is one edit
    # from aws-mq.
    gives_way = {
        name
        for name in beginning
        if len(bare) <= _SHORT and any(key not in titles[name] for key in near)
    }
    leads = [name for name in beginning if name not in gives_way]

    if not (named or aliased):
        # Words are compared whole, so ``gemini`` begins ``gemini agent
        # platform`` and ``gem`` begins nothing. The shorter name is the closer
        # one. A name the caller published takes part beside the curated ones,
        # and comes first among names as long, because the list says what each
        # of its ThreatModels is called and the curated table only guesses at
        # what a pack is called. "AWS Systems" begins the title "AWS Systems
        # Manager", so it leads to aws-ssm ahead of keys only spelled a little
        # like it.
        leading = [(len(name), 0, name, titles[name]) for name in leads]
        leading += [
            (len(name), 1, name, aliases[name])
            for name in aliases
            if name.startswith(f"{bare}-")
        ]
        for *_, keys in sorted(leading, key=lambda entry: entry[:3]):
            take(keys, firmly=True)

    # A near miss of a curated alias is a likely slip, because the alias is the
    # one name its pack goes by. A near miss of a name the caller published
    # competes with it here, by ratio and first on a tie, so "Secret Manger"
    # leads to the title Secret Manager before the alias "secrets manager". It
    # is let in only to answer a curated near miss, at least as close as the
    # weakest of them, and only when it is closer than every key it does not
    # lead to is spelled. Otherwise it is scored with the keys below, where a
    # key spelled nearer the query still comes first.
    near_aliases = _close(bare, aliases, _ALIAS_CUTOFF)
    near_titles = _close(bare, titles, _ALIAS_CUTOFF)
    misses = [(score, 1, name, aliases[name]) for score, name in near_aliases]
    if near_aliases:
        weakest = near_aliases[-1][0]
        misses += [
            (score, 0, name, titles[name])
            for score, name in near_titles
            if score >= weakest
            and all(
                other < score
                for key, other in spelling.items()
                if key not in titles[name]
            )
        ]
    for _, _, _, keys in sorted(misses, key=lambda miss: (-miss[0], *miss[1:3])):
        take(keys, firmly=True)

    # How close a name the caller published is, by key. It is scored beside the
    # spellings below, because a title that is a near miss of the query can
    # belong to a key whose own spelling is a nearer one: "firestor" is a slip
    # of Firestore, and a near miss of the title Filestore.
    titled: dict[str, float] = {}
    # The order in which a published name first reaches each key. Two
    # ThreatModels can publish the same name once a bracket is cut, as "API
    # Gateway" is Google's title and AWS's cut short, and the one whose whole
    # title it is was listed first by `_by_name`, so it keeps that place on a
    # tie, where the keys' spelling would put them in any order.
    reached: dict[str, int] = {}

    def credit(names: Iterable[str], score: float) -> None:
        for name in names:
            for key in titles[name]:
                if key in allowed:
                    titled[key] = max(titled.get(key, 0.0), score)
                    reached.setdefault(key, len(reached))

    credit(leads, _ALIAS_CUTOFF)
    for score, name in near_titles:
        credit([name], score)

    best = {
        key: max(spelling.get(key, 0.0), titled.get(key, 0.0))
        for key in spelling.keys() | titled.keys()
    }

    def rank(key: str) -> tuple[float, bool, bool, int, str]:
        # A key spelled as near as a title is placed by its spelling, so a slip
        # of a key is never put behind a title that is only as close.
        by_title = titled.get(key, 0.0) > spelling.get(key, 0.0)
        return (
            -best[key],
            bool(provider) and _provider(key) != provider,
            by_title,
            reached[key] if by_title else 0,
            key,
        )

    for key in sorted(best, key=rank):
        take([key], firmly=best[key] >= _ALIAS_CUTOFF)

    if len(bare) <= _SHORT:
        # A short name is also compared one edit at a time, with each key's
        # service and then with each name it is published under, so "awf"
        # reaches the title "AWS WAF". The titles that gave way come last.
        take(sorted(near))
        take(
            sorted(
                key
                for name in titles
                if _within_one_edit(bare, name)
                for key in titles[name]
            )
        )
        for name in sorted(gives_way, key=lambda name: (len(name), name)):
            take(titles[name])
    if provider:
        # When a name leads to another provider's key exactly, the typed
        # provider has to answer it with a firm match of its own. A slight
        # likeness, such as eks to kms, is not an answer.
        named_elsewhere = any(_provider(key) != provider for key in exact)
        close = firm if named_elsewhere else set(found)
        if any(_provider(key) == provider for key in close):
            found = [key for key in found if _provider(key) == provider]
    if named:
        meant = {*named, *spelled}
        found = [key for key in found if key in meant] or found
    return found[:limit]


def suggest(
    query: str,
    candidates: Iterable[str],
    *,
    limit: int = 3,
    extra_aliases: Mapping[str, Iterable[str]] | None = None,
) -> list[str]:
    """Choose the packs or ThreatModels a mistyped or renamed name meant.

    Args:
        query: The name as typed, such as ``ec3``, ``aws-ec3`` or
            ``Gemini Agent Platform``.
        candidates: The keys the caller's key can list. Nothing else is ever
            returned.
        limit: How many to return at most.
        extra_aliases: Other names for some candidates, by key, the best known
            first, which count for this call only. The caller reads them from
            the same list it took the candidates from, such as each
            ThreatModel's title, so a ThreatModel's official name leads to it.
            A name for a key that is not a candidate leads nowhere. Such a name
            says what its ThreatModel is called, so it outranks a curated alias
            that is as close, and it is evidence about one key and no more than
            that, so a key typed with a slip is never led away from by another
            ThreatModel's title that happens to be a little like the slip.

    Returns:
        Up to ``limit`` of the candidates, best first, without repeats: those
        a published name or an alias names exactly, or whose service is the
        query, then those whose published name or alias begins with the
        query's words, then those an alias, or a published name nearer than
        any other key is spelled, nearly names, then those whose service is
        spelled close to the query or whose published name begins with its
        words or is spelled close to it, ranked together by how close each is,
        then, for a query of four characters or fewer, those whose service or
        published name is one edit away. Keys are compared by their service
        alone, and the provider the query begins with, typed as a word, with a
        slip, or run into the service, only narrows and orders: when one of
        its candidates is close by name or by service, the other providers'
        candidates are left out, unless a name leads to another provider's key
        exactly, or another provider's service is the query, and none of the
        typed provider's candidates is as close as an alias has to be. Empty
        when nothing is close, when the query is itself a candidate, or when
        it names only a vendor, such as ``aws``. When the query is a published
        name exactly, only the candidates that name leads to, and those whose
        service is the query, are returned.
    """
    pool = list(dict.fromkeys(candidates))
    published = _by_name(extra_aliases) if extra_aliases else {}
    full = _canonical(query)
    known = {_service(key) for key in pool} | {
        word for name in (*ALIASES, *published) for word in name.split("-")
    }
    provider, bare = _typed_provider(full, normalize(query), known)
    if bare in _VENDORS:
        # A vendor names no service. The keys closest to it in spelling are
        # just that vendor's shortest ones, which would read as a guess.
        return []
    return _rank(
        query,
        pool,
        full=full,
        bare=bare,
        aliases=ALIASES,
        limit=limit,
        provider=provider,
        published=published,
    )


def suggest_provider(query: str) -> list[str]:
    """Choose the providers a mistyped provider meant.

    Args:
        query: The provider as typed, such as ``gpc`` or ``Google``.

    Returns:
        The providers of `PROVIDERS` it is close to, by the rules of
        `suggest`, with the vendors' own names (``amazon``, ``google``,
        ``microsoft``) as aliases. Empty when the query is itself a provider.
    """
    canonical = _canonical(query)
    return _rank(
        query,
        PROVIDERS,
        full=canonical,
        bare=canonical,
        aliases=_PROVIDER_NAMES,
        limit=len(PROVIDERS),
    )


def did_you_mean(
    suggestions: Sequence[str], labels: Mapping[str, str] | None = None
) -> str:
    """Render suggestions as the sentence that ends a "not found" message.

    Args:
        suggestions: The keys, best first.
        labels: A title for some keys, such as a ThreatModel's, shown after
            the key in brackets. A key without one, or with an empty one, is
            named alone.

    Returns:
        ``Did you mean a?``, ``Did you mean a or b?`` or ``Did you mean a, b
        or c?``, and the empty string when there is nothing to suggest.
    """
    named = [
        f"{key} ({labels[key]})" if labels and labels.get(key) else key
        for key in suggestions
    ]
    if not named:
        return ""
    listed = named[0] if len(named) == 1 else f"{', '.join(named[:-1])} or {named[-1]}"
    return f"Did you mean {listed}?"

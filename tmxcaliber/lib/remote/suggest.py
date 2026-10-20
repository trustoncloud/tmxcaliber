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
from collections.abc import Collection, Iterable, Mapping, Sequence
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

#: How close a key, or a key's service, has to be, which is difflib's own
#: default. Release keys are short single words, so a near miss there is far
#: less likely to be a shared word that names nothing.
_KEY_CUTOFF: Final[float] = 0.6

#: The longest query that is also compared one edit at a time. A short name
#: scores low on a ratio even when one key was hit wrong, as ``s4`` scores 0.5
#: against ``s3``, while one edit of a longer name is already a close ratio.
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
    meets an alias written without a vendor. `suggest` still compares the
    whole key separately, so the provider is not lost.

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


def _merged(
    first: Mapping[str, tuple[str, ...]], second: Mapping[str, tuple[str, ...]]
) -> Mapping[str, tuple[str, ...]]:
    """Join two tables of keys by normalized name.

    Args:
        first: One table, whose keys come first where a name is in both.
        second: The other.

    Returns:
        A table with every name of either, naming the keys of both, once each.
        Passed the names a list publishes as ``first``, a ThreatModel's own
        title outranks an alias that reads the same and leads elsewhere, as
        ``Gemini Enterprise`` leads to its ThreatModel before it leads to
        Vertex AI.
    """
    table = dict(first)
    for name, keys in second.items():
        table[name] = tuple(dict.fromkeys((*table.get(name, ()), *keys)))
    return MappingProxyType(table)


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
    close by its whole spelling or by its service alone, and both lists have to
    be ranked together.

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
    published: Collection[str] = (),
) -> list[str]:
    """Choose the candidates a query most likely meant, best first.

    Args:
        query: The name as typed.
        candidates: The names that may be suggested.
        full: The query with every word kept, to compare with whole keys.
        bare: The query as aliases are stored, to compare with aliases and
            with each key's service.
        aliases: Each alternative name, and the keys it can mean.
        limit: How many to return at most.
        provider: The provider the query names, when it begins with one.
        published: The keys that a name the caller itself published, such as a
            ThreatModel's title, leads to when it is the query exactly.

    Returns:
        Up to ``limit`` candidates, in this order: aliases the query names
        exactly; aliases whose first words are the query's words, which is how
        a name is cut short; aliases it nearly names (`_ALIAS_CUTOFF`); keys
        whose whole spelling or whose service is close (`_KEY_CUTOFF`); and,
        for a short query (`_SHORT`), keys whose service is one edit away.
        Nothing when the query is itself a candidate, because there is nothing
        to correct. Only the candidate itself when the query spells one in
        another case or with other separators, such as ``AWS_EC2``.

        When the query names a provider and a candidate of that provider is
        close by its name or its service, only the candidates of that provider
        are returned. Otherwise the typed provider is the slip, as in
        ``aws-bigquery``, and the service decides.

        A candidate that is only a little like the service (below
        `_ALIAS_CUTOFF`) does not count as close when an alias names the service
        exactly for another provider. ``aws-kms`` names no AWS pack, but
        ``aws-eks`` scores 0.67 against ``kms``, and counting it would drop
        Google's Cloud KMS, the one pack the alias names, and leave only wrong
        suggestions.

        A query that is exactly a name the caller published is no slip of the
        keys, so what follows the candidates that name leads to would only be
        noise, and they alone are returned.
    """
    pool = list(dict.fromkeys(candidates))
    if limit < 1 or not bare or query in pool:
        return []
    allowed = set(pool)
    if full in allowed:
        # Every key that shares its provider also scores well against it, and
        # beside the key it plainly names those would only be noise.
        return [full]
    found: list[str] = []
    # The keys found by a name or by a service. A key found only because its
    # whole spelling shares the typed provider's prefix is not among them: it
    # says nothing about which service was meant, so it must not be taken for a
    # close candidate of the provider the query names.
    grounded: set[str] = set()
    # The keys found by an alias, or by a service spelled as close as an alias
    # has to be. Only these can outweigh an alias that names another provider's
    # key exactly.
    firm: set[str] = set()

    def take(
        keys: Iterable[str], *, grounds: bool = True, firmly: bool = False
    ) -> None:
        for key in keys:
            if key not in allowed:
                continue
            if grounds:
                grounded.add(key)
            if firmly:
                firm.add(key)
            if key not in found:
                found.append(key)

    exact = [key for key in aliases.get(bare, ()) if key in allowed]
    take(exact, firmly=True)
    if not found:
        # A name that is already an alias is not cut short, so ``ec2`` does not
        # also lead to ``ec2 auto scaling``. Words are compared whole, so
        # ``gemini`` begins ``gemini agent platform`` and ``gem`` begins
        # nothing. The shorter alias is the closer one.
        leading = (name for name in aliases if name.startswith(f"{bare}-"))
        for name in sorted(leading, key=lambda name: (len(name), name)):
            take(aliases[name], firmly=True)
    for _, name in _close(bare, aliases, _ALIAS_CUTOFF):
        take(aliases[name], firmly=True)

    # A key counts by the better of its two comparisons, so aws-ec2 ranks by
    # its whole spelling for aws-ec3 and by its service for ec3.
    whole = {key: score for score, key in _close(full, pool, _KEY_CUTOFF)}
    by_service: dict[str, list[str]] = {}
    for key in pool:
        by_service.setdefault(_service(key), []).append(key)
    service = {
        key: score
        for score, name in _close(bare, by_service, _KEY_CUTOFF)
        for key in by_service[name]
    }
    best = {
        key: max(whole.get(key, 0.0), service.get(key, 0.0))
        for key in whole.keys() | service.keys()
    }
    for key in sorted(best, key=lambda key: (-best[key], key)):
        take(
            [key],
            grounds=key in service,
            firmly=service.get(key, 0.0) >= _ALIAS_CUTOFF,
        )

    if len(bare) <= _SHORT:
        take(sorted(key for key in pool if _within_one_edit(bare, _service(key))))
    if provider:
        # When an alias names another provider's key exactly, the typed
        # provider has to answer it with a firm match of its own. A slight
        # likeness, such as eks to kms, is not an answer.
        named_elsewhere = any(_provider(key) != provider for key in exact)
        close = firm if named_elsewhere else grounded
        if any(_provider(key) == provider for key in close):
            found = [key for key in found if _provider(key) == provider]
    named = [key for key in found if key in published]
    return (named or found)[:limit]


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
            first, added to `ALIASES` for this call and ranked before it. The
            caller reads them from the same list it took the candidates from,
            such as each ThreatModel's title, so a ThreatModel's official name
            leads to it. A name for a key that is not a candidate leads
            nowhere.

    Returns:
        Up to ``limit`` of the candidates, best first, without repeats: those
        an alias names exactly, then those whose alias begins with the query's
        words, then those an alias nearly names, then those whose key or
        service is spelled close to the query, then, for a query of four
        characters or fewer, those whose service is one edit away. When the
        query begins with a provider and one of its candidates is close by name
        or by service, the other providers' candidates are left out, unless an
        alias names the service exactly for another provider and none of the
        typed provider's candidates is as close as an alias has to be. Empty
        when nothing is close, when the query is itself a candidate, or when it
        names only a vendor, such as ``aws``.
    """
    bare = normalize(query)
    if bare in _VENDORS:
        # A vendor names no service. The keys closest to it in spelling are
        # just that vendor's shortest ones, which would read as a guess.
        return []
    full = _canonical(query)
    published = _by_name(extra_aliases) if extra_aliases else {}
    return _rank(
        query,
        candidates,
        full=full,
        bare=bare,
        aliases=_merged(published, ALIASES) if published else ALIASES,
        limit=limit,
        provider=_PROVIDER_OF.get(full.partition("-")[0]),
        published=published.get(bare, ()),
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

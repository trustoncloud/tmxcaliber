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
from collections.abc import Iterable, Mapping, Sequence
from difflib import SequenceMatcher
from types import MappingProxyType
from typing import Final

#: Words that name a vendor and not a service. A leading one is dropped when it
#: stands as its own word, so ``Amazon EC2``, ``AWS EC2`` and ``ec2`` read
#: alike, while ``gcp`` inside ``gcpvertex`` is left alone.
_VENDORS: Final[frozenset[str]] = frozenset(
    {"amazon", "aws", "google", "gcp", "azure", "microsoft"}
)

#: A run of anything other than a lowercase letter or a digit. Spaces,
#: underscores and slashes are the separators people type, and treating every
#: other mark the same way lets ``Elastic Compute Cloud (EC2)`` reach an alias
#: as well.
_SEPARATORS: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

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
        "colab enterprise",
    ),
    "gcp-notebooks": ("vertex ai workbench", "workbench", "notebooks"),
    "gcp-gke": ("gke", "kubernetes engine", "google kubernetes engine"),
    "gcp-cloudsql": ("cloud sql",),
    "gcp-cloudkms": ("cloud kms",),
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


def _by_name(names: Mapping[str, tuple[str, ...]]) -> Mapping[str, tuple[str, ...]]:
    """Turn a table of names by key into a table of keys by normalized name.

    Args:
        names: Each release key, and the names people use for it.

    Returns:
        Each normalized name, and the keys it can mean, read-only. Two
        spellings that normalize alike, such as ``kubernetes engine`` and
        ``google kubernetes engine``, share one entry.
    """
    table: dict[str, tuple[str, ...]] = {}
    for key, alternatives in names.items():
        for name in alternatives:
            normal = normalize(name)
            keys = table.get(normal, ())
            if key not in keys:
                table[normal] = (*keys, key)
    return MappingProxyType(table)


#: Each normalized alternative name, and the release keys it can mean.
ALIASES: Final[Mapping[str, tuple[str, ...]]] = _by_name(_NAMES)


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


def _rank(
    query: str,
    candidates: Iterable[str],
    *,
    full: str,
    bare: str,
    aliases: Mapping[str, tuple[str, ...]],
    limit: int,
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

    Returns:
        Up to ``limit`` candidates, in this order: aliases the query names
        exactly; aliases it nearly names (`_ALIAS_CUTOFF`); keys whose whole
        spelling or whose service is close (`_KEY_CUTOFF`); and, for a short
        query (`_SHORT`), keys whose service is one edit away. Nothing when
        the query is itself a candidate, because there is nothing to correct.
        Only the candidate itself when the query spells one in another case
        or with other separators, such as ``AWS_EC2``.
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

    def take(keys: Iterable[str]) -> None:
        for key in keys:
            if key in allowed and key not in found:
                found.append(key)

    take(aliases.get(bare, ()))
    for _, name in _close(bare, aliases, _ALIAS_CUTOFF):
        take(aliases[name])

    # A key counts by the better of its two comparisons, so aws-ec2 ranks by
    # its whole spelling for aws-ec3 and by its service for ec3.
    best: dict[str, float] = {}
    for score, key in _close(full, pool, _KEY_CUTOFF):
        best[key] = max(best.get(key, 0.0), score)
    by_service: dict[str, list[str]] = {}
    for key in pool:
        by_service.setdefault(_service(key), []).append(key)
    for score, service in _close(bare, by_service, _KEY_CUTOFF):
        for key in by_service[service]:
            best[key] = max(best.get(key, 0.0), score)
    take(sorted(best, key=lambda key: (-best[key], key)))

    if len(bare) <= _SHORT:
        take(sorted(key for key in pool if _within_one_edit(bare, _service(key))))
    return found[:limit]


def suggest(query: str, candidates: Iterable[str], *, limit: int = 3) -> list[str]:
    """Choose the packs or ThreatModels a mistyped or renamed name meant.

    Args:
        query: The name as typed, such as ``ec3``, ``aws-ec3`` or
            ``Gemini Agent Platform``.
        candidates: The keys the caller's key can list. Nothing else is ever
            returned.
        limit: How many to return at most.

    Returns:
        Up to ``limit`` of the candidates, best first, without repeats: those
        an alias names exactly, then those an alias nearly names, then those
        whose key or service is spelled close to the query, then, for a query
        of four characters or fewer, those whose service is one edit away.
        Empty when nothing is close, when the query is itself a candidate, or
        when it names only a vendor, such as ``aws``.
    """
    bare = normalize(query)
    if bare in _VENDORS:
        # A vendor names no service. The keys closest to it in spelling are
        # just that vendor's shortest ones, which would read as a guess.
        return []
    return _rank(
        query,
        candidates,
        full=_canonical(query),
        bare=bare,
        aliases=ALIASES,
        limit=limit,
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

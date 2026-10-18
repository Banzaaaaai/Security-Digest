"""Conservative report-time deduplication of independently classified coverage.

Keep storage intact. Compare original members, never a growing merged summary,
so a roundup cannot transitively join otherwise unrelated incidents.
"""

import re
import unicodedata
from copy import deepcopy
from datetime import datetime, timedelta

from rapidfuzz.fuzz import token_set_ratio

from .normalize import canonical_url

# These words describe coverage or attack mechanics, rather than identify the
# affected organization/product. Distinct topic names must survive comparison.
_GENERIC = set(
    """a an and are as at be been being by for from has have in into is it its of on
    or that the their this to via was were with without new latest after before
    about over through under across against more than also may can could should
    attackers attacker hackers hacker attack attacks attacking breach breaches
    breached compromise compromised compromises credential credentials used uses
    using use access accesses accessed targets targeting target affects affected
    affecting hits hit abuse abused abusing campaign campaigns customer customers
    organizations organization company companies firms services service supply chain
    issue issues security cybersecurity cyber critical high flaw flaws vulnerability
    vulnerabilities bug bugs patch patches patched patching fixes fix update updates
    released releases release reports report warns warning discovers discovered
    finds found reveals revealed linked related incident incidents ongoing confirms
    confirmed investigates investigation cloud backup tenants tenant environments
    environment researchers research exploited exploitation active
    actively data theft stolen steals steal leak leaks leaked""".split()
)


def _words(text):
    return re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", text))


def _text(text):
    return " ".join(word.casefold() for word in _words(text))


def _topics(text):
    return {word.casefold() for word in _words(text)} - _GENERIC


def _names(item):
    # Also protect victims/actors named only in the summary. This deliberately
    # favors keeping uncertain matches over discarding a separate incident.
    return {
        word.casefold()
        for word in _words(item["headline"] + " " + item["summary"])
        if any(char.isupper() for char in word)
    } - _GENERIC


def same_story(left, right, options):
    ids_a = {a["advisory_id"] for a in left["articles"] if a.get("advisory_id")}
    ids_b = {a["advisory_id"] for a in right["articles"] if a.get("advisory_id")}
    if ids_a and ids_b and ids_a.isdisjoint(ids_b):
        return False
    a, b = left["classification"], right["classification"]
    latest_a = max(datetime.fromisoformat(article["published"]) for article in left["articles"])
    latest_b = max(datetime.fromisoformat(article["published"]) for article in right["articles"])
    if abs(latest_a - latest_b) > timedelta(hours=options.get("window_hours", 48)):
        return False
    # Sharing a vendor, or one CVE in a roundup, is insufficient evidence.
    if a["cves"] and b["cves"] and set(a["cves"]) != set(b["cves"]):
        return False
    if a["regulations"] != b["regulations"]:
        return False
    non_incidents = {"regulation_policy", "research", "vendor_product", "law_enforcement"}
    if a["category"] != b["category"] and {a["category"], b["category"]} & non_incidents:
        return False
    topics_a, topics_b = _topics(a["headline"]), _topics(b["headline"])
    if not topics_a & topics_b or (topics_a - topics_b and topics_b - topics_a):
        return False
    names_a, names_b = _names(a), _names(b)
    if names_a - names_b and names_b - names_a:
        return False
    if a["threat_actors"] and b["threat_actors"]:
        if {_text(x) for x in a["threat_actors"]}.isdisjoint(_text(x) for x in b["threat_actors"]):
            return False
    return token_set_ratio(_text(a["headline"]), _text(b["headline"])) >= options.get(
        "headline_similarity", 70
    ) and token_set_ratio(_text(a["summary"]), _text(b["summary"])) >= options.get("summary_similarity", 65)


def _union(values):
    result = []
    for value in values:
        if value not in result:
            result.append(deepcopy(value))
    return result


def _merge(group, config):
    result = deepcopy(group[0])
    if len(group) == 1:
        return result
    result["merged_cluster_ids"] = sorted(
        {ident for member in group for ident in member.get("merged_cluster_ids", [member["id"]])}
    )
    articles = {}
    for member in group:
        for article in member["articles"]:
            url = canonical_url(article["url"])
            if url not in articles:
                articles[url] = {**deepcopy(article), "url": url}
            else:
                for field in ("cves", "attack_techniques", "links"):
                    articles[url][field] = _union([*articles[url][field], *article[field]])
    result["articles"] = list(articles.values())
    item = result["classification"]
    # Retain the representative's prose and relevance scores; combine validated
    # evidence, then let scoring recompute overrides from original model values.
    for field in (
        "cves",
        "affected_technologies",
        "threat_actors",
        "attack_techniques",
        "detection_refs",
        "countries_mentioned",
    ):
        item[field] = _union(value for member in group for value in member["classification"][field])
    strongest = max(
        (member["classification"] for member in group),
        key=lambda value: config.scoring["importance_points"][value["importance"]],
    )
    item["importance"] = strongest["importance"]
    item["importance_rationale"] = strongest["importance_rationale"]
    if not group[0]["classification"]["detection_refs"] and item["detection_refs"]:
        with_rules = max(
            (member["classification"] for member in group),
            key=lambda value: len(value["detection_refs"]),
        )
        item["detection_coverage_note"] = with_rules["detection_coverage_note"]
    return result


def deduplicate(config, ranked_clusters):
    """Merge matching classified clusters in representative-preference order."""
    options = config.scoring.get("post_dedup", {})
    groups = []
    for cluster in ranked_clusters:
        for group in groups:
            if all(same_story(cluster, member, options) for member in group):
                group.append(cluster)
                break
        else:
            groups.append([cluster])
    return [_merge(group, config) for group in groups]

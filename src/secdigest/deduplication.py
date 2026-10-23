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

# Reporting verbs and timing describe an event, but do not identify it. Keep
# product, victim, actor and component names out of this vocabulary.
_COVERAGE = set(
    """says say said detects detected detection attempts attempt attempting exploit
    exploiting started starts start began begins begin early first initial days day
    four before after public disclosure disclosed disclosures wider awareness
    patches patch rollout released releases release issued issuing maintainers
    vendors vendor defenders alerted alerts notification notified probed probing
    respond response responses rush companies researchers analysts intelligence
    threat evidence reports reported reporting indicates indicate potential risk
    zero actively active warns warning critical flaws vulnerabilities""".split()
)
_MECHANICS = {
    "sql_injection": r"\bsql injection\b",
    "xss": r"\b(?:xss|cross site scripting)\b",
    "buffer_overflow": r"\bbuffer overflow\b",
    "use_after_free": r"\buse after free\b",
    "path_traversal": r"\b(?:path|directory) traversal\b",
}
_ROUNDUP = re.compile(r"\b(?:roundup|round up|weekly digest|news recap|week in review)\b", re.I)
_PROSE_GENERIC = set(
    """widely deployed deployment infrastructure software systems system web server
    servers side soon broader broad rapid weaponization common relevant relevance
    highly immediate urgent urgency available detail details technical limited
    provides provide provided identifier score severity product products enterprise
    points frames suggests indicates source article cluster activity though remain
    possible pre direct impact advisory needed""".split()
)
_TECHNICAL_TERMS = {"sql", "cve", "rce", "cvss", "api", "oauth", "devsecops", "ci", "cd", "mfa"}


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


def _contains(text, phrase):
    return f" {phrase} " in f" {_text(text)} "


def _source_text(cluster):
    return " ".join(a["title"] + " " + a["summary"] for a in cluster["articles"])


def _subjects(cluster):
    """Use classified products only when supported by both headline and sources."""
    item = cluster["classification"]
    return {
        _text(tech)
        for tech in item["affected_technologies"]
        if _topics(tech)
        and _contains(item["headline"], _text(tech))
        and _contains(_source_text(cluster), _text(tech))
    }


def _event_names(cluster):
    # Distinctive vulnerability/campaign names (e.g. Log4Shell) can identify
    # an event when a short feed omits the CVE. A product name alone cannot.
    item = cluster["classification"]
    technology_words = {w for tech in item["affected_technologies"] for w in _words(_text(tech))}
    return {
        word.casefold()
        for word in _words(item["headline"])
        if len(word) >= 6
        and (re.search(r"[a-z][A-Z]", word) or (re.search(r"\d", word) and re.search(r"[a-zA-Z]", word)))
        and word.casefold() not in technology_words
        and _contains(_source_text(cluster), word.casefold())
    }


def _conflicting_mechanisms(a, b):
    mechanics = [
        {
            key
            for key, pattern in _MECHANICS.items()
            if re.search(pattern, _text(i["headline"] + " " + i["summary"]))
        }
        for i in (a, b)
    ]
    return all(mechanics) and mechanics[0].isdisjoint(mechanics[1])


def _same_event(left, right, options):
    """Match paraphrases through a supported subject plus event-specific context."""
    a, b = left["classification"], right["classification"]
    vulnerabilities = {"vulnerability", "exploitation_in_the_wild"}
    topics_a, topics_b = _topics(a["headline"]) - _COVERAGE, _topics(b["headline"]) - _COVERAGE
    shared_products = _subjects(left) & _subjects(right)
    affected_overlap = {_text(t) for t in a["affected_technologies"]} & {
        _text(t) for t in b["affected_technologies"]
    }
    technology_words = {
        word for item in (a, b) for tech in item["affected_technologies"] for word in _words(_text(tech))
    }
    names = [
        _names(item) - technology_words - _COVERAGE - _TECHNICAL_TERMS - {"administrators"} for item in (a, b)
    ]
    if names[0] - names[1] and names[1] - names[0]:
        return False
    if a["category"] in vulnerabilities and b["category"] in vulnerabilities:
        names_a, names_b = _event_names(left), _event_names(right)
        if names_a and names_b and names_a.isdisjoint(names_b):
            return False
        # Preserve differently named victims/products/campaigns. Attribution to
        # a researcher may be absent, but two different subjects cannot vanish.
        if names_a & names_b and affected_overlap:
            return not (topics_a - topics_b and topics_b - topics_a)
        if not shared_products:
            return False
        mechanism_words = {"sql", "injection", "zero", "day"}
        topics_a, topics_b = topics_a - mechanism_words, topics_b - mechanism_words
        if topics_a - topics_b and topics_b - topics_a:
            return False
        return token_set_ratio(_text(a["headline"]), _text(b["headline"])) >= options.get(
            "event_headline_similarity", 55
        ) and token_set_ratio(_text(a["summary"]), _text(b["summary"])) >= options.get(
            "event_summary_similarity", 50
        )
    if a["category"] == b["category"] == "supply_chain" and shared_products:
        # Distribution channels and tooling supply additional identity evidence;
        # publisher boilerplate and capitalized headline words are not evidence.
        context = {
            _text(tech)
            for item in (a, b)
            for tech in item["affected_technologies"]
            if _text(tech) in affected_overlap - shared_products
            and _topics(tech) - _TECHNICAL_TERMS
            and any(c.isupper() for c in tech)
            and all(_contains(_source_text(c), _text(tech)) for c in (left, right))
        }
        # Nested names such as GitHub / GitHub CLI are one context signal.
        context = {
            tech for tech in context if not any(tech != other and _contains(other, tech) for other in context)
        }
        return len(context) >= 2
    return False


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
    if a["threat_actors"] and b["threat_actors"]:
        if {_text(x) for x in a["threat_actors"]}.isdisjoint(_text(x) for x in b["threat_actors"]):
            return False
    if any(
        _ROUNDUP.search(text)
        for cluster in (left, right)
        for text in [cluster["classification"]["headline"], *[x["title"] for x in cluster["articles"]]]
    ):
        return False
    # An exact, source-validated CVE set and matching affected product identify
    # the same vulnerability even when disclosure/patch/exploitation headlines
    # differ. Never join a roundup or a separate affected-product advisory.
    vulnerability_categories = {"vulnerability", "exploitation_in_the_wild"}
    if (
        a["category"] in vulnerability_categories
        and b["category"] in vulnerability_categories
        and a["cves"]
        and set(a["cves"]) == set(b["cves"])
        and {_text(t) for t in a["affected_technologies"]} & {_text(t) for t in b["affected_technologies"]}
    ):
        return True
    if (
        a["category"] in vulnerability_categories
        and b["category"] in vulnerability_categories
        and _conflicting_mechanisms(a, b)
    ):
        return False
    if _same_event(left, right, options):
        return True
    topics_a, topics_b = _topics(a["headline"]), _topics(b["headline"])
    if not topics_a & topics_b or (topics_a - topics_b and topics_b - topics_a):
        return False
    names_a, names_b = _names(a), _names(b)
    if names_a - names_b and names_b - names_a:
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


def _merge_prose(group, field):
    """Append complementary sentences with attribution, without generating claims.

    Full original summaries and actions remain in source_coverage. This extractive view
    omits repeated wording and generic restatements, but keeps numbers, negation
    and uncertainty verbatim whenever a sentence is included.
    """
    result = group[0]["classification"][field]
    seen = _topics(result) - _COVERAGE - _PROSE_GENERIC
    if field == "summary":
        publishers = ", ".join(dict.fromkeys(a["source"] for a in group[0]["articles"]))
        result = publishers + ": " + result
    for member in group[1:]:
        extra = []
        for sentence in re.split(r"(?<=[.!?])\s+", member["classification"][field].strip()):
            words = _topics(sentence) - _COVERAGE - _PROSE_GENERIC
            novel = words - seen
            # A changed number or a contrary outcome matters even in a short
            # sentence. Preserve its full wording and source attribution.
            qualifiers = {"unsuccessful", "successful", "unconfirmed", "unproven", "not", "no", "never"}
            if len(novel) >= 3 or novel & qualifiers or any(re.search(r"\d", word) for word in novel):
                extra.append(sentence)
                seen.update(words)
        if extra:
            publishers = ", ".join(dict.fromkeys(a["source"] for a in member["articles"]))
            result += " " + publishers + ": " + " ".join(extra)
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
    item["source_coverage"] = _union(
        coverage
        for member in group
        for coverage in member["classification"].get(
            "source_coverage",
            [
                {
                    "cluster_id": member["id"],
                    "summary": member["classification"]["summary"],
                    "recommended_action": member["classification"]["recommended_action"],
                    "sources": [
                        {"source": a["source"], "url": canonical_url(a["url"])} for a in member["articles"]
                    ],
                }
            ],
        )
    )
    item["summary"] = _merge_prose(group, "summary")
    item["recommended_action"] = _merge_prose(group, "recommended_action")
    # Retain original relevance scores; combine validated evidence, then let
    # scoring recompute overrides from the original model values.
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

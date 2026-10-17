"""Filter model output against source evidence and configured allowlists."""

import re
from copy import deepcopy
from datetime import date

from .normalize import canonical_url, extract_ids, safe_url


def validate_claims(config, item, cluster, store):
    item = deepcopy(item)
    text = "\n".join(a["title"] + "\n" + a["summary"] for a in cluster["articles"])
    cves, _ = extract_ids(text)
    item["cves"] = sorted(set(item["cves"]) & set(cves))
    known_attack = set(store.get("attack", []))
    item["attack_techniques"] = sorted(set(item["attack_techniques"]) & known_attack)
    links = {canonical_url(url) for a in cluster["articles"] for url in a["links"] if safe_url(url)}
    item["detection_refs"] = [
        ref for ref in item["detection_refs"] if safe_url(ref["url"]) and canonical_url(ref["url"]) in links
    ]
    item["related_case_studies"] = [
        slug
        for slug in dict.fromkeys(item["related_case_studies"])
        if slug in config.case_studies
        and (
            item["industry_relevance"][config.case_studies[slug]["industry"]] >= 60
            or any(
                item["practice_area_relevance"][p] >= 60 for p in config.case_studies[slug]["practice_areas"]
            )
            or config.case_studies[slug]["country"] in item["countries_mentioned"]
        )
    ][:2]
    item["threat_actors"] = [actor for actor in item["threat_actors"] if actor.casefold() in text.casefold()]
    for regulation in item["regulations"]:
        reported = regulation["effective_or_deadline_date"]
        if reported:
            day = date.fromisoformat(str(reported))
            variants = [
                str(reported),
                day.strftime("%B %d, %Y"),
                f"{day.day} {day:%B %Y}",
                f"{day:%B} {day.day}, {day.year}",
            ]
            if not any(v.casefold() in text.casefold() for v in variants):
                regulation["effective_or_deadline_date"] = None
    # A category assertion alone is not proof of exploitation.
    if item["category"] == "exploitation_in_the_wild" and not re.search(
        r"(?:actively|active|in.the.wild|confirmed)\s+exploitat|actively\s+exploited|exploited\s+in.the.wild",
        text,
        re.I,
    ):
        item["category"] = "vulnerability"
    signal = item["business_signal"]
    if not config.settings["business_signals"]["enabled"]:
        signal["present"], signal["rationale"] = False, ""
    elif signal["present"]:
        # Do not pass unconstrained model prose into a prospecting section.
        # The signal is rebuilt using only sector/region/type allowlists.
        signal["rationale"] = (
            f"Sector-level {signal['type'].replace('_', ' ')} assessment for {config.industries[signal['sector']]['name']} in {signal['region']}; assess shared controls and obligations."
        )
    return item

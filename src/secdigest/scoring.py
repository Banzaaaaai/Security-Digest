"""Deterministic overrides always start from the original model scores."""

import logging
import re
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta

log = logging.getLogger(__name__)


def watch_matches(config, technologies):
    result = []
    for vendor, products in config.watch_tech.items():
        for product in products:
            aliases = [product["name"], *product["aliases"]]
            if any(
                re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", tech, re.I)
                for tech in technologies
                for alias in aliases
            ):
                result.append({**product, "vendor": vendor})
    return result


def score(config, cluster, store, now=None):
    now = now or datetime.now(UTC)
    item = deepcopy(cluster["classification"])
    item["sources"] = [
        {k: a[k] for k in ("url", "source", "published", "date_inferred")} for a in cluster["articles"]
    ]
    item["overrides"] = []
    levels = sorted(config.scoring["importance_points"], key=config.scoring["importance_points"].get)
    matches = watch_matches(config, item["affected_technologies"])
    item["watch_tech"] = matches
    kev, epss, cvss = store.get("kev", {}), store.get("epss", {}), store.get("cvss", {})
    item["cve_details"] = {
        cve: {"kev": kev.get(cve), "epss": epss.get(cve), "cvss": cvss.get(cve)} for cve in item["cves"]
    }

    def floor(level, reason):
        if levels.index(level) > levels.index(item["importance"]):
            item["importance"] = level
            item["overrides"].append(reason)
            log.info("Scoring override %s: %s -> %s", item["cluster_id"], reason, level)

    def raise_one(reason):
        floor(levels[min(levels.index(item["importance"]) + 1, len(levels) - 1)], reason)

    if any(
        c in kev and 0 <= (now.date() - date.fromisoformat(kev[c]["dateAdded"])).days <= 7
        for c in item["cves"]
    ):
        floor(
            "critical" if matches else "high",
            "CISA KEV added within seven days" + ("; watch technology match" if matches else ""),
        )
    if item["category"] == "exploitation_in_the_wild" and matches:
        floor("critical", "Reported in-the-wild exploitation of watch technology")
    if any(epss.get(c, 0) >= config.scoring["epss_threshold"] for c in item["cves"]):
        raise_one("EPSS meets configured threshold")
    articles = cluster["articles"]
    # Count only observations inside a 24-hour span, at or before this report's end.
    valid = [a for a in articles if datetime.fromisoformat(a["published"]) <= now]
    independent = max(
        (
            len(
                {
                    a["independence_key"]
                    for a in valid
                    if datetime.fromisoformat(anchor["published"])
                    <= datetime.fromisoformat(a["published"])
                    <= datetime.fromisoformat(anchor["published"]) + timedelta(hours=24)
                }
            )
            for anchor in valid
        ),
        default=0,
    )
    if independent >= config.scoring["independent_sources"]:
        raise_one("Three or more independent sources within 24 hours")
    regions = config.raw["regions"]
    countries = {regions["country_aliases"].get(c, c) for c in item["countries_mentioned"]}
    item["countries_mentioned"] = sorted(countries)
    for country in countries:
        region = regions["priority_countries"].get(country)
        if region:
            item["location_relevance"][region] = min(
                100, item["location_relevance"][region] + regions["country_bonus"]
            )
    if item["category"] in {"vulnerability", "exploitation_in_the_wild"} and any(
        m.get("cross_industry") for m in matches
    ):
        item["industry_relevance"] = {
            k: max(v, config.scoring["cross_industry_floor"]) for k, v in item["industry_relevance"].items()
        }
    weights = config.scoring["weights"]
    item["priority"] = round(
        weights["importance"] * config.scoring["importance_points"][item["importance"]]
        + weights["location"]
        * max((item["location_relevance"][r] for r in config.scoring["priority_regions"]), default=0)
        + weights["industry"] * max(item["industry_relevance"].values())
        + weights["practice"] * max(item["practice_area_relevance"].values()),
        2,
    )
    threshold = config.scoring["inclusion"]
    item["included"] = (
        levels.index(item["importance"]) >= levels.index(threshold["min_importance"])
        or max(
            [
                *item["location_relevance"].values(),
                *item["industry_relevance"].values(),
                *item["practice_area_relevance"].values(),
            ]
        )
        >= threshold["relevance"]
    )
    return item

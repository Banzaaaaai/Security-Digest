"""Deterministic overrides always start from the original model scores."""

import logging
import re
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta

from .risk import exposure_profile, source_signals

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
    item["model_importance"] = item["importance"]
    item["model_importance_rationale"] = item["importance_rationale"]
    severity_reasons = []
    levels = sorted(config.scoring["importance_points"], key=config.scoring["importance_points"].get)
    matches = watch_matches(config, item["affected_technologies"])
    item["watch_tech"] = matches
    kev, epss, cvss = store.get("kev", {}), store.get("epss", {}), store.get("cvss", {})
    item["cve_details"] = {
        cve: {"kev": kev.get(cve), "epss": epss.get(cve), "cvss": cvss.get(cve)} for cve in item["cves"]
    }
    signals = source_signals(cluster["articles"])
    profile = exposure_profile(config, item, cluster["articles"], signals)
    item["risk_evidence"] = signals
    item["exposure_scope"] = profile["name"] if profile else "Source-specific or unestablished"
    recent_kev = any(
        c in kev and 0 <= (now.date() - date.fromisoformat(kev[c]["dateAdded"])).days <= 7
        for c in item["cves"]
    )
    known_exploitation = any(
        c in kev and date.fromisoformat(kev[c]["dateAdded"]) <= now.date() for c in item["cves"]
    )
    active_exploitation = bool(signals["exploitation_reported"])
    systemic_compromise = bool(signals["supply_chain_compromise"] and profile and profile["systemic"])

    def floor(level, reason):
        if levels.index(level) > levels.index(item["importance"]):
            item["importance"] = level
            item["overrides"].append(reason)
            severity_reasons.append(reason)
            log.info("Scoring override %s: %s -> %s", item["cluster_id"], reason, level)

    # A critical CVSS/PoC/emergency patch alone does not establish an ongoing
    # critical incident. Apply the same rubric to cached and new classifications.
    if (
        item["category"] in {"vulnerability", "exploitation_in_the_wild"}
        and item["importance"] == "critical"
        and not (active_exploitation or recent_kev or systemic_compromise)
    ):
        item["importance"] = "high"
        reason = "No source-reported exploitation or recent KEV evidence; vulnerability capped at high"
        item["overrides"].append(reason)
        severity_reasons.append(reason)
    if recent_kev:
        floor(
            "critical" if profile and profile["systemic"] else "high",
            "CISA KEV added within seven days"
            + ("; source-supported widespread technology" if profile and profile["systemic"] else ""),
        )
    if known_exploitation:
        floor("high", "CISA KEV records exploitation; old entries do not establish a new active campaign")
    if active_exploitation and item["category"] in {"vulnerability", "exploitation_in_the_wild"}:
        item["category"] = "exploitation_in_the_wild"
        floor(
            "critical" if profile and profile["systemic"] else "high",
            "Source-reported exploitation or KEV; deployment breadth determines urgency",
        )
    if systemic_compromise:
        floor(
            "critical", "Source-reported compromise of widely distributed software or supplier infrastructure"
        )
    if signals["certificate_compromise"]:
        floor("high", "Source-reported certificate or signing-key compromise")
    if signals["critical_flaw"] and (signals["rce"] or signals["emergency_patch"] or signals["public_poc"]):
        if item["category"] in {"vulnerability", "exploitation_in_the_wild", "vendor_product"}:
            floor("high", "Source-supported critical flaw with RCE, emergency remediation or public PoC")
    if any(epss.get(c, 0) >= config.scoring["epss_threshold"] for c in item["cves"]):
        floor("high", "EPSS meets configured threshold; probability alone does not establish exploitation")
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
    item["independent_sources_24h"] = independent
    regions = config.raw["regions"]
    countries = {regions["country_aliases"].get(c, c) for c in item["countries_mentioned"]}
    item["countries_mentioned"] = sorted(countries)
    if profile:
        item["location_relevance"] = {
            region: profile["location_floor"] for region in item["location_relevance"]
        }
        item["industry_relevance"] = {
            industry: max(value, profile["industry_floor"])
            for industry, value in item["industry_relevance"].items()
        }
        item["overrides"].append(
            f"Global deployment applicability: every region {profile['location_floor']}%; "
            f"cross-industry relevance at least {profile['industry_floor']}%"
        )
    else:
        # At most one bonus per region. For global software exposure, reporting
        # country or publisher location must not bias deployment applicability.
        for region in {
            regions["priority_countries"][c] for c in countries if c in regions["priority_countries"]
        }:
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
    components = {
        "importance": weights["importance"] * config.scoring["importance_points"][item["importance"]],
        "location": weights["location"]
        * max(item["location_relevance"][r] for r in config.scoring["priority_regions"]),
        "industry": weights["industry"] * max(item["industry_relevance"].values()),
        "practice": weights["practice"] * max(item["practice_area_relevance"].values()),
    }
    raw_priority = sum(components.values())
    lower, upper = config.scoring["priority_bands"][item["importance"]]
    item["priority"] = round(max(lower, min(upper, raw_priority)), 2)
    item["priority_breakdown"] = {
        **{key: round(value, 2) for key, value in components.items()},
        "weighted_total": round(raw_priority, 2),
        "severity_band": [lower, upper],
    }
    if item["importance"] != item["model_importance"]:
        item["importance_rationale"] = "; ".join(severity_reasons) + "."
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

"""Build report data once, then render the same facts in every output format."""

from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from .deduplication import deduplicate
from .scheduling import window
from .scoring import score
from .synthesis import synthesize


def heatmap(config, items, taxonomy, field):
    threshold = config.settings["weekly"]["heatmap_min_relevance"]
    return [
        {
            "key": key,
            "name": value["name"],
            "cells": {
                level: {"count": len(values), "average": round(sum(values) / len(values), 1) if values else 0}
                for level in config.scoring["importance_points"]
                for values in [
                    [i[field][key] for i in items if i["importance"] == level and i[field][key] >= threshold]
                ]
            },
        }
        for key, value in taxonomy.items()
    ]


def trends(items):
    return {
        "exploited_technologies": dict(
            Counter(
                t
                for i in items
                if i["category"] == "exploitation_in_the_wild"
                or any(d["kev"] for d in i["cve_details"].values())
                for t in i["affected_technologies"]
            )
        ),
        "threat_actors": dict(Counter(t for i in items for t in i["threat_actors"])),
        "attack_techniques": dict(Counter(t for i in items for t in i["attack_techniques"])),
        "categories": dict(Counter(i["category"] for i in items)),
    }


def report_items(config, clusters, store, end):
    """Deduplicate before all totals, trends, synthesis and output rendering."""
    clusters = [
        {
            **cluster,
            "articles": [a for a in cluster["articles"] if datetime.fromisoformat(a["published"]) < end],
        }
        for cluster in clusters
    ]
    classified = [c for c in clusters if c["classification"] and c["articles"]]
    scored = {c["id"]: score(config, c, store, end) for c in classified}
    ranked = sorted(
        classified,
        key=lambda c: (
            -config.scoring["importance_points"][scored[c["id"]]["importance"]],
            -scored[c["id"]]["priority"],
            scored[c["id"]]["headline"],
            c["id"],
        ),
    )
    merged = deduplicate(config, ranked)
    items = []
    for cluster in merged:
        item = scored[cluster["id"]]
        if "merged_cluster_ids" in cluster:
            item = score(config, cluster, store, end)
            item["merged_cluster_ids"] = cluster["merged_cluster_ids"]
        items.append(item)
    return merged, sorted(items, key=lambda i: (-i["priority"], i["headline"]))


def build_report(config, store, kind, period=None, now=None, dry_run=False, synthesis_client=None):
    start, end, period = window(config, kind, period, now)
    clusters = store.clusters(start, end)
    pending = sum(c["classification"] is None for c in clusters)
    classified_count = len(clusters) - pending
    clusters, items = report_items(config, clusters, store, end)
    counts = {
        level: sum(i["importance"] == level for i in items) for level in config.scoring["importance_points"]
    }
    new_kev = [
        {"cve": cve, **value}
        for cve, value in store.get("kev", {}).items()
        if start.astimezone(ZoneInfo(config.settings["timezone"])).date()
        <= date.fromisoformat(value["dateAdded"])
        <= (end - timedelta(microseconds=1)).astimezone(ZoneInfo(config.settings["timezone"])).date()
    ]
    watch, regulations, cases = defaultdict(list), defaultdict(list), defaultdict(list)
    for item in items:
        for tech in item["watch_tech"]:
            watch[tech["vendor"]].append(
                {"technology": tech["name"], "headline": item["headline"], "cluster_id": item["cluster_id"]}
            )
        for reg in item["regulations"]:
            details = config.regulations[reg["key"]]
            regulations[details["region"]].append(
                {**reg, "name": details["name"], "headline": item["headline"], "sources": item["sources"]}
            )
        for slug in item["related_case_studies"]:
            cases[slug].append(item["cluster_id"])
    report = {
        "kind": kind,
        "period": period,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "timezone": config.settings["timezone"],
        "synthetic": dry_run,
        "items": items,
        "counts": counts,
        "unclassified": pending,
        "duplicates_removed": classified_count - len(items),
        "new_kev": new_kev,
        "watch_hits": sum(bool(i["watch_tech"]) for i in items),
        "watch": dict(watch),
        "regulations": dict(regulations),
        "other_count": sum(not i["included"] for i in items),
        "source_health": store.get("source_health", {}),
        "enrichment_warnings": store.get("enrichment_warnings", []),
        "kev_provenance": store.get("kev:provenance", {}),
        "coverage_notes": [] if dry_run else config.raw["feeds"].get("coverage_notes", []),
        "cases": dict(cases),
    }
    if kind == "daily":
        return report
    previous_start = (start.astimezone(ZoneInfo(config.settings["timezone"])) - timedelta(days=7)).astimezone(
        UTC
    )
    previous_clusters = store.clusters(previous_start, start)
    _, previous = report_items(config, previous_clusters, store, start)
    current_trends, old_trends = trends(items), trends(previous)
    for name, values in old_trends.items():
        for key in values:
            current_trends[name].setdefault(key, 0)
    deltas = (
        {
            kind: {key: count - old_trends[kind].get(key, 0) for key, count in values.items()}
            for kind, values in current_trends.items()
        }
        if previous
        else None
    )
    cve_table = {}
    for item in items:
        for cve, details in item["cve_details"].items():
            row = cve_table.setdefault(cve, {**details, "watch_tech": [], "sources": []})
            row["watch_tech"] = sorted(set(row["watch_tech"]) | {t["name"] for t in item["watch_tech"]})
            # Count sources that actually mention this CVE, not every cluster member.
            members = next(c["articles"] for c in clusters if c["id"] == item["cluster_id"])
            row["sources"] = sorted(set(row["sources"]) | {a["source"] for a in members if cve in a["cves"]})
    regional = {}
    priority = config.raw["regions"]["priority_countries"]
    country_map = {**priority, **config.raw["regions"].get("country_regions", {})}
    for region in config.scoring["priority_regions"]:
        countries = defaultdict(list)
        for item in items:
            if item["location_relevance"][region] < 60:
                continue
            involved = [
                c
                for c in item["countries_mentioned"]
                if country_map.get(c, max(item["location_relevance"], key=item["location_relevance"].get))
                == region
            ]
            for country in involved or ["Regional relevance"]:
                countries[country].append(item["cluster_id"])
        regional[region] = dict(
            sorted(countries.items(), key=lambda pair: (pair[0] not in priority, pair[0]))
        )
    calendar, needs_dates = [], []
    for key, regulation in config.regulations.items():
        if regulation["needs_dates"]:
            needs_dates.append(regulation["name"])
        for milestone in regulation["milestones"]:
            if end.date() <= date.fromisoformat(str(milestone["date"])) <= end.date() + timedelta(days=90):
                calendar.append({"key": key, "name": regulation["name"], **milestone})
    report.update(
        industry_heatmap=heatmap(config, items, config.industries, "industry_relevance"),
        practice_heatmap=heatmap(config, items, config.practice_areas, "practice_area_relevance"),
        regional=regional,
        trends=current_trends,
        deltas=deltas,
        previous_count=len(previous),
        cve_table=cve_table,
        calendar=sorted(calendar, key=lambda x: str(x["date"])),
        needs_dates=needs_dates,
        detection_gaps=[
            i["cluster_id"]
            for i in items
            if i["importance"] in {"critical", "high"} and not i["detection_refs"]
        ],
        business_signals=[i["business_signal"] for i in items if i["business_signal"]["present"]]
        if config.settings["business_signals"]["enabled"]
        else None,
        watchlist=[
            {
                "headline": i["headline"],
                "action": i["recommended_action"],
                "status": "Remediation status not established by this digest",
                "sources": i["sources"],
            }
            for i in items
            if i["category"] == "exploitation_in_the_wild" or any(d["kev"] for d in i["cve_details"].values())
        ],
    )
    report["synthesis"] = synthesize(config, store, items, period, dry_run, synthesis_client)
    return report

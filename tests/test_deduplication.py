from copy import deepcopy
from datetime import timedelta

import pytest

from secdigest.deduplication import deduplicate
from secdigest.fixtures import FIXTURE_NOW
from secdigest.rendering import csv_text, render_html, render_markdown
from secdigest.reporting import build_report, report_items
from secdigest.storage import Store

CONNECTWISE = [
    (
        "Compromised ConnectWise credential used to access Microsoft 365 tenants",
        "Attackers are abusing a compromised ConnectWise Cloud Backup credential to sign in to "
        "Microsoft 365 tenants. The campaign targets customer environments through a trusted "
        "MSP-related account path.",
    ),
    (
        "ConnectWise supply-chain compromise hits Microsoft 365 tenants",
        "Attackers abused a ConnectWise cloud backup supply-chain issue to access application "
        "identities and compromise Microsoft 365 tenants. Organizations using the service should "
        "review identity trust, rotate credentials, and check for unauthorized access paths.",
    ),
]


@pytest.fixture
def story(populated):
    template = populated.clusters()[0]

    def make(ident, text=CONNECTWISE[0], age=1, **fields):
        cluster = deepcopy(template)
        cluster["id"] = ident
        item = cluster["classification"]
        item.update(
            cluster_id=ident,
            headline=text[0],
            summary=text[1],
            category="supply_chain",
            importance="high",
            cves=[],
            threat_actors=[],
            regulations=[],
            attack_techniques=[],
            detection_refs=[],
            countries_mentioned=["NL"],
            affected_technologies=["ConnectWise Cloud Backup", "Microsoft 365"],
        )
        item.update(fields)
        item["location_relevance"]["Europe"] = 30
        article = cluster["articles"][0]
        article.update(
            title=text[0],
            summary=text[1],
            cves=item["cves"].copy(),
            url=f"https://{ident}.example.test/story",
            source=ident,
            independence_key=ident,
            published=(FIXTURE_NOW - timedelta(hours=age)).isoformat(),
        )
        cluster["articles"] = [article]
        return cluster

    return make


def save(store, config, clusters):
    for cluster in clusters:
        for article in cluster["articles"]:
            store.add_article(article, cluster["id"])
        if cluster["classification"]:
            store.classify(cluster["id"], cluster["classification"], config.fingerprint, "fixture")


def test_distinct_advisory_ids_are_not_merged(config, story):
    left, right = story("left"), story("right")
    left["articles"][0]["advisory_id"] = "ICSA-26-001-01"
    right["articles"][0]["advisory_id"] = "ICSA-26-001-02"
    assert len(deduplicate(config, [left, right])) == 2


def test_connectwise_paraphrases_merge_after_classification(config, populated, story):
    clusters = [
        story("thn", category="vulnerability"),
        story("security-nl", CONNECTWISE[1]),
        story("bleeping", CONNECTWISE[1]),
    ]
    clusters[1]["articles"][0]["title"] = "Supplychain-aanval via ConnectWise raakt tal van bedrijven"
    clusters[1]["classification"]["affected_technologies"].append("SkyKick Cloud Backup")
    clusters[2]["classification"]["attack_techniques"] = ["T1078"]
    clusters[2]["classification"]["detection_refs"] = [
        {"type": "sigma", "url": "https://bleeping.example.test/rule"}
    ]
    clusters[2]["classification"]["detection_coverage_note"] = "Source-linked Sigma rule is available."
    original = deepcopy(clusters)
    merged, items = report_items(config, clusters, populated, FIXTURE_NOW)
    assert len(merged) == len(items) == 1
    item = items[0]
    assert {s["source"] for s in item["sources"]} == {"thn", "security-nl", "bleeping"}
    assert item["merged_cluster_ids"] == ["bleeping", "security-nl", "thn"]
    assert "SkyKick Cloud Backup" in item["affected_technologies"]
    assert item["attack_techniques"] == ["T1078"]
    assert len(item["detection_refs"]) == 1
    assert item["detection_coverage_note"] == "Source-linked Sigma rule is available."
    assert item["importance"] == "critical"  # Source-supported systemic compromise.
    assert item["location_relevance"]["Europe"] == 85
    assert clusters == original
    assert deduplicate(config, merged) == merged
    assert report_items(config, original[::-1], populated, FIXTURE_NOW)[1] == items


def test_identical_drupal_coverage_merges(config, story):
    text = (
        "Drupal fixes critical remote code execution flaws",
        "Drupal released security updates for critical flaws that could let attackers execute code "
        "on affected sites. The advisory indicates exploitation may follow soon, so exposed "
        "deployments should prioritize patching and validation.",
    )
    clusters = [
        story(name, text, affected_technologies=["Drupal"], category="vulnerability")
        for name in ("security-nl", "bleeping")
    ]
    assert len(deduplicate(config, clusters)) == 1


@pytest.mark.parametrize(
    "difference",
    [
        "different_cve",
        "cve_roundup",
        "different_victim",
        "victim_in_summary",
        "different_product",
        "different_actor",
        "old_incident",
        "regulation_event",
        "research",
    ],
)
def test_related_but_distinct_stories_stay_separate(config, story, difference):
    left, right = story("a"), story("b")
    a, b = left["classification"], right["classification"]
    if difference in {"different_cve", "cve_roundup"}:
        a["cves"] = ["CVE-2026-10001"]
        b["cves"] = ["CVE-2026-10002"]
        if difference == "cve_roundup":
            b["cves"].extend(a["cves"])
    elif difference in {"different_victim", "victim_in_summary"}:
        for item, victim in ((a, "Northwind"), (b, "Contoso")):
            item["summary"] = f"{victim} reported unauthorized access to its Microsoft 365 tenants."
            if difference == "different_victim":
                item["headline"] = f"{victim} Microsoft 365 tenants breached through stolen credentials"
    elif difference == "different_product":
        a["headline"] = "Microsoft fixes critical Outlook vulnerability"
        b["headline"] = "Microsoft fixes critical Exchange vulnerability"
    elif difference == "different_actor":
        a["threat_actors"], b["threat_actors"] = ["Actor One"], ["Actor Two"]
    elif difference == "old_incident":
        right["articles"][0]["published"] = (FIXTURE_NOW - timedelta(hours=50)).isoformat()
    elif difference == "regulation_event":
        for item, nature in ((a, "guidance"), (b, "enforcement")):
            item["regulations"] = [{"key": "dora", "nature": nature, "effective_or_deadline_date": None}]
    elif difference == "research":
        b["category"] = "research"
    assert len(deduplicate(config, [left, right])) == 2


def test_roundup_does_not_transitively_merge_different_incidents(config, story):
    clusters = [
        story(
            name,
            (
                f"{victim} cloud credential compromise",
                f"Attackers used stolen credentials to access {victim} cloud environments.",
            ),
        )
        for name, victim in (("a", "Aster"), ("roundup", "Aster and Boreal"), ("b", "Boreal"))
    ]
    assert len(deduplicate(config, clusters)) == 2


def test_same_source_url_is_kept_once_and_evidence_retained(config, story):
    left, right = story("a"), story("b")
    right["articles"][0]["url"] = left["articles"][0]["url"] + "?utm_source=rss"
    right["articles"][0]["links"] = ["https://rules.example.test/detection"]
    merged = deduplicate(config, [left, right])[0]
    assert len(merged["articles"]) == 1
    assert merged["articles"][0]["links"] == ["https://rules.example.test/detection"]


def test_future_sources_do_not_affect_historical_report_or_mutate_inputs(config, populated, story):
    current = story("current")
    future = story("future", CONNECTWISE[1], age=-1)
    current["articles"].extend(future["articles"])
    original = deepcopy(current)
    merged, items = report_items(config, [current], populated, FIXTURE_NOW)
    assert len(merged[0]["articles"]) == len(items[0]["sources"]) == 1
    assert current == original


def test_daily_outputs_and_counts_use_unique_incidents(config, story):
    store = Store(":memory:")
    clusters = [story("a"), story("b", CONNECTWISE[1]), story("c", CONNECTWISE[1])]
    pending = story("pending")
    pending["classification"] = None
    save(store, config, [*clusters, pending])
    before = store.clusters()
    report = build_report(config, store, "daily", now=FIXTURE_NOW)
    assert report["duplicates_removed"] == 2
    assert report["unclassified"] == 1
    assert report["counts"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert report["watch_hits"] == 1
    assert len(report["items"]) == 1
    summary = report["items"][0]["summary"]
    for rendered in (
        render_markdown(config, report),
        render_html(config, report),
        render_html(config, report, email=True),
        csv_text(config, report),
    ):
        assert rendered.count(summary) == 1
        for cluster in clusters:
            assert cluster["articles"][0]["url"] in rendered
    assert store.clusters() == before
    assert not store.was_sent("daily", report["period"])
    assert build_report(config, store, "daily", now=FIXTURE_NOW) == report
    store.close()


def test_weekly_counts_cve_sources_deltas_and_synthesis_are_deduplicated(config, story, monkeypatch):
    store = Store(":memory:")
    cve = "CVE-2026-10001"
    current = [story("a", cves=[cve]), story("b", CONNECTWISE[1], cves=[cve]), story("c", CONNECTWISE[1])]
    previous = [story("old-a", age=169, cves=[cve]), story("old-b", age=170, cves=[cve])]
    save(store, config, [*current, *previous])
    received = []

    def synthesis(config, store, items, *args):
        received.extend(items)
        return {}

    monkeypatch.setattr("secdigest.reporting.synthesize", synthesis)
    report = build_report(config, store, "weekly", "2026-W42", now=FIXTURE_NOW)
    assert len(report["items"]) == len(received) == 1
    assert report["previous_count"] == 1
    assert report["trends"]["categories"] == {"supply_chain": 1}
    assert report["deltas"]["categories"] == {"supply_chain": 0}
    assert report["cve_table"][cve]["sources"] == ["a", "b"]
    assert max(cell["count"] for row in report["industry_heatmap"] for cell in row["cells"].values()) == 1
    store.close()

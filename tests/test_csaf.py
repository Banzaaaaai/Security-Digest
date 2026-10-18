import asyncio
import json
import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from secdigest.csaf import parse_csaf, parse_rolie
from secdigest.sources import Fetcher, check_feeds, ingest
from secdigest.storage import Store

NOW = datetime(2026, 10, 18, tzinfo=UTC)
RELEASED = "2026-10-17T08:00:00Z"
BASE = "https://example.test/csaf/"


def feed(channel="IT"):
    return {
        "name": "CISA " + channel,
        "url": BASE + channel + ".json",
        "type": "csaf",
        "enabled": True,
        "document_base_url": BASE,
        "independence_key": "cisa.gov",
        "source_name": "CISA",
    }


def entry(ident="VA-26-001-01", updated=RELEASED):
    return {
        "id": ident,
        "published": RELEASED,
        "updated": updated,
        "content": {"src": BASE + ident + ".json", "type": "application/json"},
    }


def index(entries):
    return {"feed": {"category": [{"term": "csaf"}], "entry": entries}}


def document(ident="VA-26-001-01", current=RELEASED, version="1.0.0"):
    return {
        "document": {
            "csaf_version": "2.0",
            "title": "Example remote code execution",
            "publisher": {"name": "CISA"},
            "tracking": {
                "id": ident,
                "initial_release_date": RELEASED,
                "current_release_date": current,
                "version": version,
            },
            "notes": [{"category": "summary", "text": "Attackers can run arbitrary code."}],
            "references": [{"category": "self", "url": "https://www.cisa.gov/advisory/" + ident}],
        },
        "product_tree": {"branches": [{"product": {"product_id": "p1", "name": "Example Server 1"}}]},
        "vulnerabilities": [
            {
                "cve": "CVE-2026-12345",
                "title": "Code execution",
                "notes": [{"category": "summary", "text": "Authentication is not required."}],
                "product_status": {"known_affected": ["p1"]},
                "scores": [{"cvss_v3": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}}],
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "Upgrade to version 2.",
                        "url": "https://vendor.test/fix",
                    }
                ],
            }
        ],
    }


def setup(config, feeds=None):
    config.settings["http"]["per_host_delay"] = 0
    config.feeds = feeds or [feed()]
    respx.get("https://example.test/robots.txt").respond(404)
    return Store(":memory:")


def test_parser_retains_source_facts():
    entries, errors = parse_rolie(json.dumps(index([entry()])), feed())
    article = parse_csaf(json.dumps(document()), entries[0], feed(), NOW)
    assert errors == 0
    assert article["advisory_id"] == "VA-26-001-01"
    assert article["independence_key"] == "cisa.gov"
    assert article["cves"] == ["CVE-2026-12345"]
    assert article["published"] == "2026-10-17T08:00:00+00:00"
    assert article["initial_published"] == article["published"]
    assert "Example Server 1" in article["summary"]
    assert "9.8" in article["summary"]
    assert "Upgrade to version 2." in article["summary"]
    assert "https://vendor.test/fix" in article["links"]
    assert article["url"] == "https://www.cisa.gov/advisory/VA-26-001-01"


@respx.mock
def test_cross_feed_advisory_identity_and_idempotence(config):
    store = setup(config, [feed("IT"), feed("VA")])
    for source in config.feeds:
        respx.get(source["url"]).respond(200, json=index([entry()]))
    route = respx.get(entry()["content"]["src"]).respond(200, json=document())
    first = asyncio.run(ingest(config, store, NOW))
    second = asyncio.run(ingest(config, store, NOW))
    assert first["failures"] == second["failures"] == 0
    assert first["new"] == 1
    assert second["new"] == second["updated"] == 0
    assert route.call_count == 1
    assert len(store.clusters()) == 1
    assert sum(r["unchanged"] for r in first["sources"]) == 1


@respx.mock
def test_revision_updates_existing_cluster_and_invalidates_classification(config):
    store = setup(config)
    route = respx.get(feed()["url"]).respond(200, json=index([entry()]))
    doc = respx.get(entry()["content"]["src"]).respond(200, json=document())
    asyncio.run(ingest(config, store, NOW))
    ident = store.clusters()[0]["id"]
    store.classify(ident, {"old": True}, "fingerprint", "test")
    revised = "2026-10-17T22:00:00Z"
    route.respond(200, json=index([entry(updated=revised)]))
    doc.respond(200, json=document(current=revised, version="1.1.0"))
    health = asyncio.run(ingest(config, store, NOW))
    assert health["new"] == 0 and health["updated"] == 1
    cluster = store.clusters()[0]
    assert cluster["id"] == ident and cluster["classification"] is None
    assert len(cluster["articles"]) == 1
    assert cluster["articles"][0]["initial_published"] == "2026-10-17T08:00:00+00:00"
    assert cluster["articles"][0]["advisory_version"] == "1.1.0"
    # A lagging channel must not replace the revised advisory.
    route.respond(200, json=index([entry()]))
    doc.respond(200, json=document())
    assert asyncio.run(ingest(config, store, NOW))["updated"] == 0
    assert store.clusters()[0]["articles"][0]["advisory_version"] == "1.1.0"
    store.prune(NOW)
    assert store.advisory("cisa.gov:VA-26-001-01") is None


@respx.mock
def test_failed_document_retried_when_index_returns_304(config):
    store = setup(config)
    respx.get(feed()["url"]).mock(
        side_effect=[
            httpx.Response(200, json=index([entry(), entry("VA-26-002-01")]), headers={"ETag": "v1"}),
            httpx.Response(304),
        ]
    )
    good = respx.get(entry()["content"]["src"]).respond(200, json=document())
    failed = respx.get(entry("VA-26-002-01")["content"]["src"]).mock(
        side_effect=[
            httpx.Response(404),
            httpx.Response(200, json=document("VA-26-002-01")),
        ]
    )
    first = asyncio.run(ingest(config, store, NOW))
    second = asyncio.run(ingest(config, store, NOW))
    assert first["failures"] == 1 and first["new"] == 1
    assert first["sources"][0]["failed_advisories"][0]["advisory_id"] == "VA-26-002-01"
    assert second["failures"] == 0 and second["new"] == 1
    assert good.call_count == 1 and failed.call_count == 2
    assert len(store.clusters()) == 2  # Separate advisory IDs with identical prose survive.


@respx.mock
def test_invalid_document_identity_never_advances_checkpoint(config):
    store = setup(config)
    respx.get(feed()["url"]).respond(200, json=index([entry()]))
    route = respx.get(entry()["content"]["src"]).respond(200, json=document("wrong-id"))
    assert asyncio.run(ingest(config, store, NOW))["failures"] == 1
    assert store.advisory("cisa.gov:VA-26-001-01") is None
    route.respond(200, json=document())
    assert asyncio.run(ingest(config, store, NOW))["new"] == 1


@respx.mock
def test_retention_and_future_entries_are_not_fetched(config):
    store = setup(config)
    old = entry("OLD", (NOW - timedelta(days=121)).isoformat())
    future = entry("FUTURE", (NOW + timedelta(days=1)).isoformat())
    respx.get(feed()["url"]).respond(200, json=index([old, future, entry()]))
    respx.get(entry()["content"]["src"]).respond(200, json=document())
    assert asyncio.run(ingest(config, store, NOW))["new"] == 1


@pytest.mark.parametrize(
    "url", ["https://other.test/a.json", BASE + "../a.json", BASE + "%2e%2e/a.json", BASE + "a.json?x=y"]
)
def test_out_of_scope_document_urls_are_rejected(url):
    bad = entry()
    bad["content"]["src"] = url
    entries, errors = parse_rolie(json.dumps(index([bad, entry()])), feed())
    assert len(entries) == errors == 1


@respx.mock
def test_document_redirect_cannot_leave_publisher_directory(config):
    store = setup(config)
    respx.get(BASE + "a.json").respond(302, headers={"Location": "https://outside.test/a"})

    async def check():
        async with Fetcher(config, store) as fetcher:
            with pytest.raises(ValueError, match="publisher directory"):
                await fetcher.get(BASE + "a.json", url_prefix=BASE)

    asyncio.run(check())


@respx.mock
def test_feed_check_preserves_csaf_adapter(config, monkeypatch):
    store = setup(config)
    monkeypatch.setattr(config, "save_feeds", lambda: None)
    respx.get(feed()["url"]).respond(200, json=index([entry()]))
    results = asyncio.run(check_feeds(config, store))
    assert results[0]["status"] == "ok"
    assert config.feeds[0]["type"] == "csaf"
    assert config.feeds[0]["enabled"]


@pytest.mark.parametrize("mutation", ["naive", "future", "wrong-version"])
def test_invalid_document_dates_and_format_rejected(mutation):
    value = deepcopy(document())
    if mutation == "naive":
        value["document"]["tracking"]["current_release_date"] = "2026-10-17T08:00:00"
    elif mutation == "future":
        value["document"]["tracking"]["current_release_date"] = "2027-01-01T00:00:00Z"
    else:
        value["document"]["csaf_version"] = "1.0"
    entries, _ = parse_rolie(json.dumps(index([entry()])), feed())
    with pytest.raises(ValueError):
        parse_csaf(json.dumps(value), entries[0], feed(), NOW)


def test_schema_upgrade_preserves_existing_articles_and_deliveries(tmp_path):
    path = tmp_path / "old.sqlite"
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE clusters (id TEXT PRIMARY KEY, created TEXT NOT NULL);
        CREATE TABLE articles (url TEXT PRIMARY KEY, cluster_id TEXT NOT NULL REFERENCES clusters(id),
                               published TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE deliveries (kind TEXT NOT NULL, period TEXT NOT NULL, sent TEXT NOT NULL,
                                 PRIMARY KEY(kind,period));
        INSERT INTO clusters VALUES ('old','2026-10-17T08:00:00+00:00');
        INSERT INTO articles VALUES ('https://example.test/old','old','2026-10-17T08:00:00+00:00','{}');
        INSERT INTO deliveries VALUES ('daily','2026-10-18','2026-10-18T00:00:00+00:00');
        PRAGMA user_version=1;
    """)
    old.close()
    store = Store(path)
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == 2
    assert store.article("https://example.test/old") == {}
    assert store.was_sent("daily", "2026-10-18")
    assert store.db.execute("SELECT count(*) FROM advisories").fetchone()[0] == 0
    store.close()


@respx.mock
def test_invalid_index_does_not_poison_http_cache(config):
    store = setup(config)
    respx.get(feed()["url"]).mock(
        side_effect=[
            httpx.Response(200, text="invalid-json", headers={"ETag": "broken"}),
            httpx.Response(200, json=index([entry()])),
        ]
    )
    respx.get(entry()["content"]["src"]).respond(200, json=document())
    assert asyncio.run(ingest(config, store, NOW))["failures"] == 1
    assert store.get("http:" + feed()["url"]) == {}
    assert asyncio.run(ingest(config, store, NOW))["new"] == 1


@respx.mock
def test_partial_index_keeps_good_entries_and_reports_failure(config):
    store = setup(config)
    respx.get(feed()["url"]).respond(200, json=index([entry(), {"id": "malformed"}]))
    respx.get(entry()["content"]["src"]).respond(200, json=document())
    health = asyncio.run(ingest(config, store, NOW))
    assert health["new"] == health["failures"] == 1
    assert store.get("http:" + feed()["url"]) == {}

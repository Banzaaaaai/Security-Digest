import asyncio
import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
import respx

from secdigest.classification import classification_params
from secdigest.fixtures import FIXTURE_NOW
from secdigest.html_sources import parse_html_index
from secdigest.sources import check_feeds, ingest
from secdigest.storage import Store

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(params=["amazon_linux_cves", "anthropic_research"])
def publisher(config, request):
    feed = deepcopy(next(f for f in config.feeds if f.get("parser") == request.param))
    filename = (
        "amazon-linux-index.html" if request.param == "amazon_linux_cves" else "anthropic-research.html"
    )
    return feed, (FIXTURES / filename).read_bytes()


def test_publisher_facts_dates_and_scope(publisher):
    feed, body = publisher
    articles, stats = parse_html_index(body, feed, FIXTURE_NOW)
    assert len(articles) == 2 and stats["invalid"] == 0
    assert {a["published"] for a in articles} == {"2026-10-16T00:00:00+00:00", "2026-10-15T00:00:00+00:00"}
    assert all(not a["date_inferred"] and a["date_precision"] == "day" for a in articles)
    assert all(a["independence_key"] == feed["independence_key"] for a in articles)
    assert "&" in articles[0]["summary"]
    if feed["parser"] == "amazon_linux_cves":
        assert stats["ignored"] == 1
        assert articles[0]["cves"] == ["CVE-2026-90001"]
        assert "not establish Amazon Linux affected status" in articles[0]["summary"]
        assert "not Amazon Linux advisory" in articles[0]["date_basis"]
    else:
        assert articles[1]["url"].startswith("https://www.anthropic.com/institute/")
        assert "Not a rendered article" not in str(articles)


@pytest.mark.parametrize("replacement", [b"not-a-date", b"", b"2026-02-30"])
def test_invalid_date_is_partial_never_inferred(publisher, replacement):
    feed, body = publisher
    date = b"2026-10-16" if feed["parser"] == "amazon_linux_cves" else b"Oct 16, 2026"
    articles, stats = parse_html_index(body.replace(date, replacement, 1), feed, FIXTURE_NOW)
    assert len(articles) == 1 and stats["invalid"] == 1
    assert not articles[0]["date_inferred"]


def test_future_dated_entry_excluded(publisher):
    feed, body = publisher
    date = b"2026-10-16" if feed["parser"] == "amazon_linux_cves" else b"Oct 16, 2026"
    articles, stats = parse_html_index(body.replace(date, b"2099-01-01", 1), feed, FIXTURE_NOW)
    assert len(articles) == 1 and stats["future"] == 1 and stats["invalid"] == 0


@pytest.mark.parametrize(
    "href", [b"https://example.test/foreign", b"javascript:alert(1)", b"/research/../private"]
)
def test_untrusted_links_rejected(publisher, href):
    feed, body = publisher
    original = (
        b"./CVE-2026-90001.html" if feed["parser"] == "amazon_linux_cves" else b"/research/example-assessment"
    )
    articles, stats = parse_html_index(body.replace(original, href), feed, FIXTURE_NOW)
    assert len(articles) == 1 and stats["invalid"] == 1


def test_changed_layout_and_truncated_document_fail(publisher):
    feed, body = publisher
    with pytest.raises(ValueError):
        parse_html_index(b"<html>Temporarily unavailable</html>", feed, FIXTURE_NOW)
    with pytest.raises(ValueError):
        parse_html_index(
            body[: body.index(b"</td>" if feed["parser"] == "amazon_linux_cves" else b"</h3>")],
            feed,
            FIXTURE_NOW,
        )
    if feed["parser"] == "amazon_linux_cves":
        with pytest.raises(ValueError, match="columns changed"):
            parse_html_index(body.replace(b"Public Date", b"Last Updated"), feed, FIXTURE_NOW)


@respx.mock
def test_ingestion_retention_conditional_requests_and_repeat(publisher, config):
    feed, body = publisher
    config.feeds = [feed]
    config.settings["http"]["per_host_delay"] = 0
    config.settings["retention"]["database_days"] = 2
    host = urlsplit(feed["url"])
    respx.get(f"{host.scheme}://{host.netloc}/robots.txt").respond(404)
    route = respx.get(feed["url"]).mock(
        side_effect=[
            httpx.Response(200, content=body, headers={"ETag": '"index-v1"'}),
            httpx.Response(304),
            httpx.Response(200, content=body),
        ]
    )
    store = Store(":memory:")
    try:
        first = asyncio.run(ingest(config, store, FIXTURE_NOW))
        second = asyncio.run(ingest(config, store, FIXTURE_NOW))
        store.put("http:" + feed["url"], {})
        repeat = asyncio.run(ingest(config, store, FIXTURE_NOW))
        assert first["new"] == 1  # The 15 October entry is outside the two-day window.
        assert second["new"] == repeat["new"] == first["failures"] == repeat["failures"] == 0
        assert route.calls[1].request.headers["If-None-Match"] == '"index-v1"'
        assert "If-None-Match" not in route.calls[2].request.headers
    finally:
        store.close()


@respx.mock
def test_partial_parse_retries_without_conditional_cache(publisher, config):
    feed, body = publisher
    config.feeds = [feed]
    config.settings["http"]["per_host_delay"] = 0
    date = b"2026-10-16" if feed["parser"] == "amazon_linux_cves" else b"Oct 16, 2026"
    host = urlsplit(feed["url"])
    respx.get(f"{host.scheme}://{host.netloc}/robots.txt").respond(404)
    route = respx.get(feed["url"]).mock(
        side_effect=[
            httpx.Response(200, content=body.replace(date, b"unknown", 1), headers={"ETag": '"bad"'}),
            httpx.Response(200, content=body),
        ]
    )
    store = Store(":memory:")
    try:
        partial = asyncio.run(ingest(config, store, FIXTURE_NOW))
        recovered = asyncio.run(ingest(config, store, FIXTURE_NOW + timedelta(minutes=1)))
        assert partial["failures"] == partial["new"] == 1
        assert partial["sources"][0]["invalid"] == 1
        assert recovered["failures"] == 0 and recovered["new"] == 1
        assert "If-None-Match" not in route.calls[1].request.headers
    finally:
        store.close()


@pytest.mark.parametrize("blocked", ["robots", "redirect", "oversize"])
@respx.mock
def test_fetch_policy_still_applies(publisher, config, blocked):
    feed, body = publisher
    config.feeds = [feed]
    host = urlsplit(feed["url"])
    respx.get(f"{host.scheme}://{host.netloc}/robots.txt").respond(403 if blocked == "robots" else 404)
    if blocked == "redirect":
        respx.get(feed["url"]).respond(302, headers={"Location": "https://example.test/outside"})
    elif blocked == "oversize":
        config.settings["http"]["max_bytes"] = 10
        respx.get(feed["url"]).respond(200, content=body)
    store = Store(":memory:")
    try:
        health = asyncio.run(ingest(config, store, FIXTURE_NOW))
        assert health["failures"] == 1 and health["new"] == 0
        assert not store.clusters()
    finally:
        store.close()


@respx.mock
def test_source_check_preserves_html_type(publisher, config, monkeypatch):
    feed, body = publisher
    config.feeds = [feed]
    monkeypatch.setattr(config, "save_feeds", lambda: None)
    host = urlsplit(feed["url"])
    respx.get(f"{host.scheme}://{host.netloc}/robots.txt").respond(404)
    respx.get(feed["url"]).respond(200, content=body)
    store = Store(":memory:")
    try:
        checked = asyncio.run(check_feeds(config, store))
        assert checked[0]["status"] == "ok" and checked[0]["items"] == 2
        assert feed["enabled"] and feed["type"] == "html_index"
    finally:
        store.close()


def test_unknown_html_publisher_configuration_rejected(config):
    feed = next(f for f in config.feeds if f.get("type") == "html_index")
    feed["url"] = "https://example.test/index"
    with pytest.raises(ValueError, match="supported publisher"):
        config.validate()


def test_date_only_records_overlap_daily_window_without_changing_timestamped_sources(publisher, config):
    feed, body = publisher
    articles, _ = parse_html_index(body, feed, FIXTURE_NOW)
    source = articles[0]
    store = Store(":memory:")
    try:
        store.add_article(source, "date-only")
        exact = {**source, "url": source["url"] + "?exact", "date_precision": "second"}
        store.add_article(exact, "exact")
        # A morning digest must not lose yesterday's posts merely because their
        # publisher gives no time of day. Exact timestamps keep existing behavior.
        start, end = FIXTURE_NOW - timedelta(days=1), FIXTURE_NOW
        candidates = store.clusters(start, end)
        assert {c["id"] for c in candidates} == {"date-only"}
        assert not store.clusters(FIXTURE_NOW.replace(hour=0), end)
        assert not store.clusters(start - timedelta(days=1), start.replace(hour=0))
        params = classification_params(config, candidates)
        documents = json.loads(params["input"][0]["content"])
        assert documents[0]["sources"][0]["date_precision"] == "day"
        assert documents[0]["sources"][0]["date_basis"] == source["date_basis"]
    finally:
        store.close()

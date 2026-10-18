import asyncio
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import respx

from secdigest.fixtures import FIXTURE_NOW
from secdigest.sources import Fetcher, check_feeds, ingest, parse_feed
from secdigest.storage import Store


@respx.mock
def test_etag_304_and_robots_redirect(config):
    config.settings["http"]["per_host_delay"] = 0
    store = Store(":memory:")
    respx.get("https://example.test/robots.txt").mock(
        return_value=httpx.Response(302, headers={"Location": "/policy.txt"})
    )
    respx.get("https://example.test/policy.txt").mock(
        return_value=httpx.Response(200, text="User-agent: *\nDisallow: /private")
    )
    route = respx.get("https://example.test/feed").mock(
        side_effect=[httpx.Response(200, content=b"data", headers={"ETag": '"v1"'}), httpx.Response(304)]
    )

    async def check():
        async with Fetcher(config, store) as fetcher:
            assert await fetcher.get("https://example.test/feed") == b"data"
            assert await fetcher.get("https://example.test/feed") is None
            with pytest.raises(ValueError, match="robots"):
                await fetcher.get("https://example.test/private")

    asyncio.run(check())
    assert route.calls[1].request.headers["If-None-Match"] == '"v1"'


@respx.mock
def test_discovery_uses_redirected_directory(config, monkeypatch):
    store = Store(":memory:")
    config.feeds = [
        {"name": "Fixture", "site": "https://example.test/blog", "url": "TODO_VERIFY", "enabled": False}
    ]
    monkeypatch.setattr(config, "save_feeds", lambda: None)
    respx.get("https://example.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get("https://example.test/blog").mock(
        return_value=httpx.Response(301, headers={"Location": "/blog/"})
    )
    respx.get("https://example.test/blog/").mock(
        return_value=httpx.Response(
            200, text='<link rel="alternate" type="application/rss+xml" href="feed.xml">'
        )
    )
    respx.get("https://example.test/blog/feed.xml").mock(
        return_value=httpx.Response(200, content=(Path(__file__).parent / "fixtures/news.xml").read_bytes())
    )
    results = asyncio.run(check_feeds(config, store))
    assert results[0]["status"] == "ok"
    assert results[0]["url"] == "https://example.test/blog/feed.xml"


@respx.mock
def test_ingest_idempotent_with_live_protocol(config):
    store = Store(":memory:")
    config.feeds = [{"name": "Fixture", "url": "https://example.test/feed", "enabled": True, "type": "rss"}]
    respx.get("https://example.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get("https://example.test/feed").mock(
        return_value=httpx.Response(200, content=(Path(__file__).parent / "fixtures/news.xml").read_bytes())
    )
    first = asyncio.run(ingest(config, store, FIXTURE_NOW))
    second = asyncio.run(ingest(config, store, FIXTURE_NOW + timedelta(minutes=5)))
    assert first["new"] == 2
    assert second["new"] == 0
    assert len(store.clusters()) == 2


def category_feed(ids):
    items = "".join(
        f"<item><title>Research {i}</title><link>https://example.test/category/research</link>"
        f'<guid isPermaLink="false">{ident}</guid><pubDate>Fri, 16 Oct 2026 12:00:00 GMT</pubDate>'
        "</item>"
        for i, ident in enumerate(ids)
    )
    return f'<rss version="2.0"><channel><title>Research</title>{items}</channel></rss>'.encode()


@respx.mock
def test_opt_in_post_ids_preserve_distinct_articles_and_repeat_ingestion(config):
    config.feeds = [
        {
            "name": "Research",
            "url": "https://example.test/feed",
            "type": "rss",
            "enabled": True,
            "entry_url_field": "id",
        }
    ]
    config.settings["http"]["per_host_delay"] = 0
    store = Store(":memory:")
    payload = category_feed(["https://example.test/?p=101", "https://example.test/?p=102"])
    respx.get("https://example.test/robots.txt").respond(404)
    respx.get("https://example.test/feed").respond(200, content=payload)
    first = asyncio.run(ingest(config, store, FIXTURE_NOW))
    second = asyncio.run(ingest(config, store, FIXTURE_NOW))
    assert first["new"] == 2
    assert second["new"] == 0
    urls = {a["url"] for c in store.clusters() for a in c["articles"]}
    assert urls == {"https://example.test/?p=101", "https://example.test/?p=102"}


@pytest.mark.parametrize("ident", ["not-a-url", "javascript:alert(1)", "https://other.test/?p=1", ""])
def test_opt_in_post_ids_reject_unusable_or_external_ids(ident):
    feed = {"name": "Research", "url": "https://example.test/feed", "entry_url_field": "id"}
    assert parse_feed(category_feed([ident]), feed, FIXTURE_NOW) == []


def test_default_feed_url_still_uses_link():
    feed = {"name": "Research", "url": "https://example.test/feed"}
    rows = parse_feed(category_feed(["https://example.test/?p=101"]), feed, FIXTURE_NOW)
    assert rows[0]["url"] == "https://example.test/category/research"


def test_unknown_entry_url_field_rejected(config):
    config.feeds[0]["entry_url_field"] = "summary"
    with pytest.raises(ValueError, match="entry_url_field"):
        config.validate()

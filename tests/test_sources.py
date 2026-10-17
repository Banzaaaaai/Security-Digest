import asyncio
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import respx

from secdigest.fixtures import FIXTURE_NOW
from secdigest.sources import Fetcher, check_feeds, ingest
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

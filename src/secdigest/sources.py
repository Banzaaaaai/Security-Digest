"""Bounded async HTTP, robots policy, feed discovery and cached ingestion."""

from __future__ import annotations

import asyncio
import calendar
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import feedparser
import httpx

from .clustering import Clusterer
from .csaf import CSAFReader, parse_rolie, scoped_url
from .normalize import SourceHTML, canonical_url, extract_ids, safe_url, source_text


class Fetcher:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.semaphore = asyncio.Semaphore(config.settings["http"]["concurrency"])
        self.robots_locks = {}
        self.final_urls = {}
        self.host_next = {}
        self.client = httpx.AsyncClient(
            timeout=config.settings["http"]["timeout"],
            follow_redirects=False,
            headers={"User-Agent": config.settings["http"]["user_agent"]},
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.client.aclose()

    async def allowed(self, url):
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        lock = self.robots_locks.setdefault(origin, asyncio.Lock())
        async with lock:
            cached = self.store.get("robots-v2:" + origin)
            if not cached or datetime.fromisoformat(cached["expires"]) < datetime.now(UTC):
                robots_url = origin + "/robots.txt"
                for _ in range(6):
                    response = await self.client.get(robots_url)
                    if not response.is_redirect:
                        break
                    robots_url = str(response.url.join(response.headers["location"]))
                    if not safe_url(robots_url):
                        raise ValueError("Unsafe robots redirect")
                else:
                    raise ValueError("Too many robots redirects")
                # Missing robots.txt permits fetching; explicit denial and transient
                # server failure do not silently authorize collection.
                if response.status_code in {401, 403, 429} or response.status_code >= 500:
                    raise ValueError("robots.txt unavailable or access denied")
                content = response.text if response.status_code == 200 else ""
                cached = {"text": content, "expires": (datetime.now(UTC) + timedelta(hours=24)).isoformat()}
                self.store.put("robots-v2:" + origin, cached)
            robot = RobotFileParser()
            robot.parse(cached["text"].splitlines())
            delay = robot.crawl_delay(self.config.settings["http"]["user_agent"]) or 0
            rate = robot.request_rate(self.config.settings["http"]["user_agent"])
            if rate and rate.requests:
                delay = max(delay, rate.seconds / rate.requests)
            delay = max(delay, self.config.settings["http"].get("per_host_delay", 0.25))
            wait = self.host_next.get(origin, 0) - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self.host_next[origin] = time.monotonic() + delay
            return robot.can_fetch(self.config.settings["http"]["user_agent"], url)

    async def get(self, url, conditional=True, robots=True, max_bytes=None, url_prefix=None):
        if not safe_url(url):
            raise ValueError("Invalid source URL")
        original = url
        cache = self.store.get("http:" + original, {}) if conditional else {}
        headers = {}
        if cache.get("etag"):
            headers["If-None-Match"] = cache["etag"]
        if cache.get("modified"):
            headers["If-Modified-Since"] = cache["modified"]
        async with self.semaphore:
            for _ in range(6):
                if url_prefix and not scoped_url(url, url_prefix):
                    raise ValueError("Source redirect outside configured publisher directory")
                if robots and not await self.allowed(url):
                    raise ValueError("Disallowed by robots.txt")
                for attempt in range(3):
                    async with self.client.stream("GET", url, headers=headers) as response:
                        if response.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                            retry = response.headers.get("Retry-After", "")
                            delay = min(float(retry), 15) if retry.isdigit() else 2**attempt
                            await asyncio.sleep(delay)
                            continue
                        if response.status_code == 304:
                            self.final_urls[original] = url
                            return None
                        if response.is_redirect:
                            url = str(response.url.join(response.headers["location"]))
                            if not safe_url(url):
                                raise ValueError("Unsafe redirect")
                            headers = {}
                            break
                        response.raise_for_status()
                        limit = max_bytes or self.config.settings["http"]["max_bytes"]
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            data.extend(chunk)
                            if len(data) > limit:
                                raise ValueError("Source exceeds maximum response size")
                        if conditional:
                            self.store.put(
                                "http:" + original,
                                {
                                    "etag": response.headers.get("etag"),
                                    "modified": response.headers.get("last-modified"),
                                },
                            )
                        self.final_urls[original] = url
                        return bytes(data)
                else:
                    raise ValueError("Request retries exhausted")
            raise ValueError("Too many redirects")


def parse_feed(payload, feed, now=None):
    now = now or datetime.now(UTC)
    parsed = feedparser.parse(payload)
    if not parsed.get("version"):
        raise ValueError("Source is not an RSS or Atom feed")
    results = []
    for entry in parsed.entries:
        # Some publisher feeds repeat a category URL in every <link>. Opt in
        # only when their URL-shaped IDs have been verified as article links.
        url_field = feed.get("entry_url_field", "link")
        link = entry.get(url_field, "")
        if not safe_url(link):
            continue
        if url_field == "id" and urlsplit(link).netloc != urlsplit(feed["url"]).netloc:
            continue
        stamp = entry.get("published_parsed") or entry.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(stamp), UTC) if stamp else now
        if published > now + timedelta(minutes=5):
            continue
        text, links = source_text(entry.get("summary", ""), link)
        title, _ = source_text(entry.get("title", "Untitled"))
        cves, techniques = extract_ids(title + " " + text)
        results.append(
            {
                "url": canonical_url(link),
                "title": title[:500],
                "summary": text[:12000],
                "source": feed["name"],
                "published": published.isoformat(),
                "fetched": now.isoformat(),
                "date_inferred": not bool(stamp),
                "cves": cves,
                "attack_techniques": techniques,
                "links": links,
                "independence_key": feed.get("independence_key", urlsplit(feed["url"]).hostname),
            }
        )
    return results


async def check_feeds(config, store):
    async with Fetcher(config, store) as fetcher:

        async def check(feed):
            candidates = []
            try:
                if feed.get("type") == "csaf":
                    data = await fetcher.get(feed["url"], conditional=False)
                    entries, errors = parse_rolie(data, feed)
                    if errors:
                        raise ValueError("Invalid ROLIE entries")
                    feed.update(enabled=True, verified=True, last_error="")
                    return {
                        "name": feed["name"],
                        "status": "ok",
                        "url": feed["url"],
                        "items": len(entries),
                        "discovered_urls": [feed["url"]],
                    }
                if feed["url"] != "TODO_VERIFY":
                    candidates.append(feed["url"])
                else:
                    data = await fetcher.get(feed["site"], conditional=False)
                    parser = SourceHTML(fetcher.final_urls.get(feed["site"], feed["site"]))
                    parser.feed(data.decode("utf-8", errors="replace"))
                    candidates.extend(parser.feeds)
                for url in dict.fromkeys(candidates):
                    try:
                        data = await fetcher.get(url, conditional=False)
                        parsed = feedparser.parse(data)
                        if parsed.get("version"):
                            feed.update(url=url, enabled=True, verified=True, type="rss", last_error="")
                            return {
                                "name": feed["name"],
                                "status": "ok",
                                "url": url,
                                "items": len(parsed.entries),
                                "discovered_urls": candidates,
                            }
                    except (httpx.HTTPError, ValueError):
                        continue
                feed.update(
                    enabled=False,
                    verified=True,
                    type="page_watch" if not candidates else "rss",
                    last_error="No valid RSS/Atom feed found",
                )
            except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
                feed.update(enabled=False, verified=True, last_error=type(exc).__name__)
            return {
                "name": feed["name"],
                "status": "disabled",
                "url": feed["url"],
                "reason": feed["last_error"],
                "discovered_urls": candidates,
            }

        results = await asyncio.gather(*(check(feed) for feed in config.feeds))
    config.save_feeds()
    store.put("source_check", {"time": datetime.now(UTC).isoformat(), "results": results})
    return results


async def ingest(config, store, now=None, fetch_fulltext=False):
    now = now or datetime.now(UTC)
    enabled = [f for f in config.feeds if f.get("enabled") and f.get("type") in {"rss", "csaf"}]
    clusterer = Clusterer(config, store)
    async with Fetcher(config, store) as fetcher:
        csaf = CSAFReader(config, store, fetcher, now)

        async def collect(feed):
            if feed["type"] == "csaf":
                return await csaf.collect(feed)
            try:
                data = await fetcher.get(feed["url"])
                items = parse_feed(data, feed, now) if data is not None else []
                count = 0
                for article in items:
                    if datetime.fromisoformat(article["published"]) >= now - timedelta(
                        days=config.settings["retention"]["database_days"]
                    ):
                        count += clusterer.add(article)
                return {"name": feed["name"], "ok": True, "new": count}
            except (httpx.HTTPError, ValueError) as exc:
                return {"name": feed["name"], "ok": False, "new": 0, "error": type(exc).__name__}

        results = await asyncio.gather(*(collect(f) for f in enabled))
    health = {
        "at": now.isoformat(),
        "enabled": len(enabled),
        "failures": sum(not r["ok"] for r in results),
        "new": sum(r["new"] for r in results),
        "updated": sum(r.get("updated", 0) for r in results),
        "sources": results,
    }
    if health["new"] or health["updated"]:
        store.put("last_new", now.isoformat())
    store.put("source_health", health)
    return health

"""Verify configured HTML indexes with public HTTP and an isolated SQLite store."""

import argparse
import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from secdigest.config import Config
from secdigest.html_sources import parse_html_index
from secdigest.reporting import build_report
from secdigest.sources import Fetcher, ingest
from secdigest.storage import Store


async def verify(output):
    config = Config()
    config.feeds = [feed for feed in config.feeds if feed.get("type") == "html_index" and feed.get("enabled")]
    config.validate()
    if not config.feeds:
        raise ValueError("No enabled HTML indexes configured")
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=config.settings["retention"]["database_days"])
    evidence = {
        "checked_at": now.isoformat(),
        "collection": "SecDigest Fetcher with robots policy and size/redirect limits; in-memory SQLite",
        "retention_days": config.settings["retention"]["database_days"],
        "classification_run": False,
        "email_sent": False,
        "sources": [],
    }
    store = Store(":memory:")
    try:
        async with Fetcher(config, store) as fetcher:
            for feed in config.feeds:
                body = await fetcher.get(feed["url"], conditional=False, url_prefix=feed["url"])
                articles, stats = parse_html_index(body, feed, now)
                result = {
                    "name": feed["name"],
                    "url": feed["url"],
                    "resolved_url": fetcher.final_urls[feed["url"]],
                    "parser": feed["parser"],
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "parsed_articles": len(articles),
                    "retained_articles": sum(
                        datetime.fromisoformat(a["published"]) >= cutoff for a in articles
                    ),
                    "inferred_dates": sum(a["date_inferred"] for a in articles),
                    "newest_published": max(a["published"] for a in articles),
                    "stats": stats,
                    "samples": [
                        {
                            key: article[key]
                            for key in ("url", "title", "published", "date_basis", "date_precision")
                        }
                        for article in articles[:3]
                    ],
                }
                evidence["sources"].append(result)
                print(
                    json.dumps({key: value for key, value in result.items() if key != "samples"}), flush=True
                )
                assert not stats["invalid"]
        first = await ingest(config, store, now)
        for feed in config.feeds:
            store.put("http:" + feed["url"], {})
        repeat = await ingest(config, store, now)
        evidence["ingestion"] = {"first": first, "repeat_without_conditional_cache": repeat}
        print(json.dumps(evidence["ingestion"]), flush=True)
        assert first["failures"] == repeat["failures"] == repeat["new"] == 0
        expected = {source["name"]: source["retained_articles"] for source in evidence["sources"]}
        assert all(source["new"] == expected[source["name"]] for source in first["sources"])
        report = build_report(config, store, "daily", now=now)
        evidence["daily_window"] = {
            "start": report["start"],
            "end": report["end"],
            "unclassified_clusters": report["unclassified"],
            "date_policy": "Date-only publication days overlap the report window; exact timestamps are unchanged",
        }
        print(json.dumps(evidence["daily_window"]), flush=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    finally:
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("output/preview/html-source-verification.json"))
    asyncio.run(verify(parser.parse_args().output))

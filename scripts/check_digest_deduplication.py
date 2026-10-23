"""Check production report grouping against fixed examples, without API calls or email."""

import json
from datetime import datetime
from pathlib import Path

from secdigest.config import Config
from secdigest.normalize import canonical_url
from secdigest.reporting import build_report
from secdigest.storage import Store


def verify(config, fixture):
    store = Store(":memory:")
    try:
        for cluster in fixture["clusters"]:
            for article in cluster["articles"]:
                store.add_article(article, cluster["id"])
            store.classify(cluster["id"], cluster["classification"], config.fingerprint, "regression-fixture")
        report = build_report(
            config, store, "daily", now=datetime.fromisoformat(fixture["provenance"]["end"])
        )
    finally:
        store.close()

    expected = {frozenset(group["members"]) for group in fixture["expected_groups"]}
    actual = {frozenset(item.get("merged_cluster_ids", [item["cluster_id"]])) for item in report["items"]}
    if actual != expected or len(report["items"]) != len(expected):
        raise RuntimeError("Story grouping regression: duplicate or unrelated incidents in report")
    source_urls = {
        canonical_url(article["url"]) for cluster in fixture["clusters"] for article in cluster["articles"]
    }
    reported_urls = {source["url"] for item in report["items"] for source in item["sources"]}
    if reported_urls != source_urls:
        raise RuntimeError("Story grouping regression: source links were lost or added")
    for group in fixture["expected_groups"]:
        item = next(i for i in report["items"] if i["cluster_id"] in group["members"])
        if any(detail not in item["summary"] for detail in group.get("summary_contains", [])):
            raise RuntimeError("Story grouping regression: complementary details were lost")
    return {
        "status": "passed",
        "fixture_commit": fixture["provenance"]["commit"],
        "input_clusters": len(fixture["clusters"]),
        "output_stories": len(report["items"]),
        "duplicates_removed": report["duplicates_removed"],
        "source_urls_preserved": len(reported_urls),
    }


def main():
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "tests/fixtures/deduplication-2026-10-23.json").read_text(encoding="utf-8"))
    print(json.dumps(verify(Config(root), fixture), indent=2))


if __name__ == "__main__":
    main()

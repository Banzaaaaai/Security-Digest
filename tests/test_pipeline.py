from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secdigest.clustering import add_article
from secdigest.fixtures import FIXTURE_NOW
from secdigest.normalize import canonical_url, extract_ids, safe_url
from secdigest.scheduling import schedule_allowed, window
from secdigest.scoring import score, watch_matches
from secdigest.sources import parse_feed
from secdigest.storage import Store


def test_normalization():
    assert (
        canonical_url("HTTPS://EXAMPLE.COM:443/a?z=1&utm_medium=x&a=2#t") == "https://example.com/a?a=2&z=1"
    )
    assert extract_ids("cve-2026-12345 CVE-2026-12345 T1566.001 T1059") == (
        ["CVE-2026-12345"],
        ["T1059", "T1566.001"],
    )
    assert safe_url("javascript:alert(1)") == ""
    assert safe_url("https://user:password@example.test") == ""


def test_feed_parsing():
    data = (Path(__file__).parent / "fixtures" / "news.xml").read_bytes()
    rows = parse_feed(data, {"name": "Fixture", "url": "https://example.test/feed"}, FIXTURE_NOW)
    assert len(rows) == 2
    assert rows[0]["cves"] == ["CVE-2026-99001"]
    assert rows[0]["links"] == ["https://example.test/rules/test.yml"]
    assert rows[1]["date_inferred"] is True
    with pytest.raises(ValueError):
        parse_feed(b"<html>not a feed</html>", {})


def test_clusters_and_roundup_protection(config, populated):
    original = populated.clusters()[0]["articles"][0]
    store = Store(":memory:")
    assert add_article(config, store, original)
    assert not add_article(config, store, original)
    duplicate = {**original, "url": "https://second.test/story"}
    assert add_article(config, store, duplicate)
    assert len(store.clusters()) == 1
    unrelated = {
        **original,
        "url": "https://third.test/story",
        "title": "Monthly patch roundup for unrelated products",
        "cves": [*original["cves"], "CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"],
    }
    add_article(config, store, unrelated)
    assert len(store.clusters()) == 2


def test_overrides_country_cross_industry_and_idempotence(config, populated):
    cluster = populated.clusters()[0]
    first = score(config, cluster, populated, FIXTURE_NOW)
    second = score(config, cluster, populated, FIXTURE_NOW)
    assert first == second
    assert first["importance"] == "critical"
    assert first["location_relevance"]["US"] == 100
    assert all(v >= 40 for v in first["industry_relevance"].values())
    assert first["priority"] == 98
    assert cluster["classification"]["importance"] == "high"


def test_kev_without_watch_is_high_and_old_kev_does_not_raise(config, populated):
    cluster = deepcopy(populated.clusters()[0])
    cluster["classification"].update(affected_technologies=[], importance="low", category="vulnerability")
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "high"
    assert score(config, cluster, populated, FIXTURE_NOW + timedelta(days=10))["importance"] == "low"


def test_exploitation_floor_without_kev(config, populated):
    populated.put("kev", {})
    assert score(config, populated.clusters()[0], populated, FIXTURE_NOW)["importance"] == "critical"


def test_epss_override(config, populated):
    result = score(config, populated.clusters()[2], populated, FIXTURE_NOW)
    assert result["importance"] == "critical"
    assert any("EPSS" in reason for reason in result["overrides"])


def test_independent_sources_and_window(config, populated):
    cluster = deepcopy(populated.clusters()[1])
    cluster["classification"]["importance"] = "medium"
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "high"
    cluster["articles"][0]["independence_key"] = cluster["articles"][1]["independence_key"]
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "medium"


def test_watch_alias_word_boundaries(config):
    assert watch_matches(config, ["Azure AD"])[0]["name"] == "Entra ID"
    assert not watch_matches(config, ["Flaws in unrelated products"])


@pytest.mark.parametrize("now", [datetime(2026, 1, 12, 6, tzinfo=UTC), datetime(2026, 7, 13, 5, tzinfo=UTC)])
def test_dst_guard(config, now):
    config.settings["scheduling"]["enabled"] = True
    assert schedule_allowed(config, "daily", now)
    assert not schedule_allowed(config, "daily", now + timedelta(hours=1))
    assert schedule_allowed(config, "daily", now + timedelta(hours=1), manual=True)


def test_windows(config):
    start, end, period = window(config, "weekly", now=datetime(2026, 10, 19, 8, tzinfo=UTC))
    assert period == "2026-W42"
    assert start == datetime(2026, 10, 11, 22, tzinfo=UTC)
    assert end == datetime(2026, 10, 18, 22, tzinfo=UTC)
    start, end, _ = window(config, "daily", "2026-03-29", datetime(2026, 10, 17, tzinfo=UTC))
    assert end - start == timedelta(hours=24)
